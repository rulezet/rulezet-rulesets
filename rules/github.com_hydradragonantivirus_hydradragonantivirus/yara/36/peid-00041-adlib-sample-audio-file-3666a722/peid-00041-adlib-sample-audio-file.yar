rule PEiD_00041_Adlib_Sample_Audio_file_ {
  meta:
    description = "[Adlib Sample Audio file]"
    ep_only     = "false"

  strings:
    $a = "GOLD SAMPLE"

  condition:
    $a
}