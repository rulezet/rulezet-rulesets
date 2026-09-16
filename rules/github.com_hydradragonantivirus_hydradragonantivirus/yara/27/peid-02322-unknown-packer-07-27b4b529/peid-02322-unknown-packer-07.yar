rule PEiD_02322_Unknown_packer__07__ {
  meta:
    description = "[Unknown packer (07)]"
    ep_only     = "true"

  strings:
    $a = { 8C C8 05 ?? ?? 50 B8 ?? ?? 50 B0 ?? 06 8C D2 06 83 }

  condition:
    $a
}