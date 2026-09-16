rule case_19438_files_MalFiles_NSM_2 {
  meta:
    description = "19438 - file NSM.ini"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
    date        = "2023-10-29"
    hash1       = "60fe386112ad51f40a1ee9e1b15eca802ced174d7055341c491dee06780b3f92"

  strings:
    $s1  = ";          Controls whether the Tutor component is installed (1) on the target machine or not (Blank)" fullword ascii
    $s2  = ";          Controls whether the TechConsole component is installed (1) on the target machine or not (Blank)" fullword ascii
    $s3  = ";          Controls whether the gateway component is installation on the target machine (1) or not (Blank)" fullword ascii
    $s4  = ";          Controls whether the client component is installed (1) on the target machine or not (Blank)" fullword ascii
    $s5  = ";          Controls whether the control component is installed (1) on the target machine or not (Blank)" fullword ascii
    $s6  = ";          Controls whether the student component is installed (1) on the target machine or not (Blank)" fullword ascii
    $s7  = ";          Controls whether the PINServer component is installation on the target machine (1) or not (Blank)" fullword ascii
    $s8  = ";          Controls whether shortcut icons are placed on the target machine" fullword ascii
    $s9  = "; Scripting=<1/Blank>" fullword ascii
    $s10 = "Scripting=" fullword ascii
    $s11 = "; ScriptingIcon=<1/Blank>" fullword ascii
    $s12 = "   This is the StartMenu Items \"Script Agent\", \"Script Editor\" and \"Run Script\"" fullword ascii
    $s13 = ";          Controls whether the Scripting component is installed (1) or not (Blank)" fullword ascii
    $s14 = "ScriptingIcon=" fullword ascii
    $s15 = ";          Controls whether the student client configuration application is installed (1) on the target machine or not (Blank)" fullword ascii
    $s16 = ";          Controls whether the remote deployment application is installed on the target machine (1) or not (Blank)" fullword ascii
    $s17 = "; ConfigIcon=<1/Blank>" fullword ascii
    $s18 = "; Configurator=<1/Blank>" fullword ascii
    $s19 = ";          Controls whether shortcut icons for the control application (1) is placed on the target machine" fullword ascii
    $s20 = "; RemoteDeploy=<1/Blank>" fullword ascii

  condition:
    uint16(0) == 0x0a0d and filesize < 20KB and
    8 of them
}