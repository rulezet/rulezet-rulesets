rule PEiD_00034_ACProtect_v1_90g____Risco_software_Inc__ {
  meta:
    description = "[ACProtect v1.90g -> Risco software Inc.]"
    ep_only     = "true"

  strings:
    $a = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }

  condition:
    $a
}