rule Virus_Autorun_Win32_Neshta_A_35 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a44e8b61cd4cbbe892550f960dab1e301b98def1d40ae04707d19321a600f3cf"

  strings:
    $x1  = "%s: Process hiberfil.sys" fullword ascii
    $x2  = "%s: Process pagefile.sys" fullword ascii
    $s3  = "%s: param == NULL in COperation::Execute." fullword ascii
    $s4  = "%s: =============== Dump GPT header information ===============" fullword ascii
    $s5  = "Failed to initialize the DATARUNLIST, please try to use chkdsk.exe in command prompt to fix and retry." fullword wide
    $s6  = "Process File Record (%u/%u, %d%%)" fullword wide
    $s7  = "?%s: Failed to process $Bitmap." fullword ascii
    $s8  = "Shrinking volume (Process volume bitmap: %d%%)" fullword wide
    $s9  = "Extending volume (Process volume bitmap: %d%%)" fullword wide
    $s10 = "Process volume bitmap: %d%%" fullword wide
    $s11 = "Moving data (Process volume bitmap: %d%%)" fullword wide
    $s12 = "Failed to initialize FILE RECORD due to error in file system. Please amend it by using CHKDSK.EXE in CMD to retry. " fullword wide
    $s13 = "Failed to get BadClus info, please try to use chkdsk.exe in command prompt to fix and retry." fullword wide
    $s14 = "Failed to initialize MFT:BITMAP file due to error in file system. Please amend it by using CHKDSK.EXE in CMD to retry." fullword wide
    $s15 = "Failed to initialize $MFT file due to error in file system. Please amend it by using CHKDSK.EXE in CMD to retry." fullword wide
    $s16 = "%s: Didn't convert to NTFS, please execute this operation alone!" fullword ascii
    $s17 = "%s: ConvertPrilog operation to fail." fullword ascii
    $s18 = "%s: Failed to lock the image of the ntdll.dll module." fullword ascii
    $s19 = "%s: Copy data to target partition fail." fullword ascii
    $s20 = "Error in the process of evaluating if the boot.ini exists." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}