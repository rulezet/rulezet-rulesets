rule Virus_Injector_Trojan_Patched_BU_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.Patched.BU_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52dae631082e413d40455a113986a327982b5d767142c11a139d09c6b9d7e739"

  strings:
    $x1  = "Invalid action object.bThis file contains information not understood by the viewer. It cannot be used for this operation.)This v" wide
    $x2  = "\"avBatchExecuteDialogTitle=Run Sequence Confirmation - ^^0\"" fullword wide
    $x3  = "static_text(name: '$$$/Dialogs/BatchExecute/Commands');" fullword ascii
    $s4  = "1.  Definitions.  \"Software\" means (a) all of the contents of the files, disk(s), CD-ROM(s) or other media with which this Agr" ascii
    $s5  = "\"avNoMSAASupportMsg=This version of the Adobe Acrobat Reader does not contain support for screen readers. Information about dow" wide
    $s6  = "227.7202-1 through 227.7202-4, as applicable, the Commercial Computer Software and Commercial Computer Software Documentation ar" ascii
    $s7  = "\"avPrDescTrans4=Maintains most of the page content as vectors, rasterizing only extremely complex areas. Produces high quality " wide
    $s8  = "2.2.1.  Subject to the terms of this Agreement, you may install one copy of such Software on a computer file server within your " ascii
    $s9  = "\"$$$/Dialogs/BatchExecute=Run Sequence Confirmation\"" fullword wide
    $s10 = "\"avExecutableLinkDisAllowed=The file \\\"%s\\\" is set to be launched by this PDF file. This is currently disallowed. Please ch" wide
    $s11 = "Error in Masked Image.%There were too many color components. A feature requires PostScript 3.3Invalid alternate image for the XO" wide
    $s12 = "static_text(name: '$$$/Dialogs/BatchExecute/Input');" fullword ascii
    $s13 = "static_text(name: '$$$/Dialogs/BatchExecute/Output');" fullword ascii
    $s14 = "The table and text extraction technology was developed by BCL and licensed to Adobe by Datawatch:  www.datawatch.com: www.bclcom" ascii
    $s15 = "dialog(name: '$$$/Dialogs/BatchExecute')" fullword ascii
    $s16 = "\"avRightsAnnot=Comments - You may add sticky notes, highlights, and strikethroughs to this Adobe PDF document.  You may also ex" wide
    $s17 = "\"$$$/Dialogs/BatchEdit/Step1/Step1Label=1. Select sequence of commands:\"" fullword wide
    $s18 = "\"$$$/Dialogs/ExecMenuDialog/Instructions=Please select the menu item you want to execute from the menu bar.\"" fullword wide
    $s19 = "\"$$$/Dialogs/GetDocInfo/Author=&Author:\"" fullword wide
    $s20 = "\"$$$/Dialogs/GetDocInfo/Binding=&Binding:\"" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}