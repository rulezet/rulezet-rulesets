rule PEiD_00708_File_Analyzer_Compiled_Datafile_Version_ {
  meta:
    description = "[File Analyzer Compiled Datafile Version]"
    ep_only     = "false"

  strings:
    $a = "File Analyzer Compiled Datafile Version"

  condition:
    $a
}