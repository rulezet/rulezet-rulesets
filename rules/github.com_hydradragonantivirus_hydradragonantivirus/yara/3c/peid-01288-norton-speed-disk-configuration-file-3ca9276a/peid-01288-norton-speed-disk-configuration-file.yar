rule PEiD_01288_Norton_Speed_Disk_Configuration_file_ {
  meta:
    description = "[Norton Speed Disk Configuration file]"
    ep_only     = "false"

  strings:
    $a = "Norton Speed"

  condition:
    $a
}