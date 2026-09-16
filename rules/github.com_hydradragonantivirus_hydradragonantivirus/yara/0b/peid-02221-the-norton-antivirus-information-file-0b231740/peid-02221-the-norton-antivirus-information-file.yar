rule PEiD_02221_The_Norton_Antivirus_Information_file_ {
  meta:
    description = "[The Norton Antivirus Information file]"
    ep_only     = "false"

  strings:
    $a = "The Norton AntiVirus Information File"

  condition:
    $a
}