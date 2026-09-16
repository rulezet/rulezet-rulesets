rule PEiD_00709_File_Analyzer_Extended_Datafile_Version_ {
  meta:
    description = "[File Analyzer Extended Datafile Version]"
    ep_only     = "false"

  strings:
    $a = { 23 03 45 58 54 44 ?? ?? 3A 03 }

  condition:
    $a
}