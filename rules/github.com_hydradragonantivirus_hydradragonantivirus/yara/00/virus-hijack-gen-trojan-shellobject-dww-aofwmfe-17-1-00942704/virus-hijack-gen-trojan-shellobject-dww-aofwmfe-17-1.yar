rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2034ad6754cb68b1829d749104c4bff8868510698a15a0d6fe23d79864213dce"

  strings:
    $s1  = "P%s cannot be installed on systems with Internet Explorer version smaller than %s\\%s cannot be installed on systems with Intern" wide
    $s2  = "B%s cannot be installed on systems with JRE version smaller than %sF%s cannot be installed on systems with DirectX version small" wide
    $s3  = "Cannot access URL: %sK%s cannot be installed on systems without %s 2010 Primary Interop Assembly.-%s cannot be installed on syst" wide
    $s4  = "Could not find file %s or ImageJ.cfg. Please" fullword ascii
    $s5  = "@(\"inconsistent IOB fields\", stream->_ptr - stream->_base >= 0)" fullword wide
    $s6  = "Error loading configuration file" fullword ascii
    $s7  = "QuestionOAn upgrade of the selected instance will be performed. Do you want to continue? Upgrade all installed instances.xThis p" wide
    $s8  = "Failed>%s cannot be installed on systems running on virtual machines.F%s cannot be installed on systems without %s Primary Inter" wide
    $s9  = "Failed to create link!" fullword wide
    $s10 = "Wave Files" fullword ascii
    $s11 = "Device not created. Choose settings and click 'Create Device' then type to see results" fullword ascii
    $s12 = "Release Device" fullword ascii
    $s13 = "&Create Device" fullword ascii
    $s14 = "E(*mode == _T('\\0'))" fullword wide
    $s15 = "Preparing...L%s can not be installed on systems with Adobe Reader version smaller than %s" fullword wide
    $s16 = "Deleting extracted files...<%s cannot be installed on systems without %s 2013 or higher.EUnmatching digital signature between EX" wide
    $s17 = "reinstall the application." fullword ascii
    $s18 = "Could not start the application" fullword ascii
    $s19 = "Please reinstall the application" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}