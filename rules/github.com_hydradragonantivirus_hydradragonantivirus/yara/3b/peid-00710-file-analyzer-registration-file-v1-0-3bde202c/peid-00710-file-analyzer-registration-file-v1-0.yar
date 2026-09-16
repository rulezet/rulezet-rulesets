rule PEiD_00710_File_Analyzer_Registration_file_v1_0_ {
  meta:
    description = "[File Analyzer Registration file v1.0]"
    ep_only     = "false"

  strings:
    $a = { 24 46 41 52 45 47 24 4D 2D ?? ?? ?? ?? 31 }

  condition:
    $a
}