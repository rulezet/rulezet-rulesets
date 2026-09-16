rule PEiD_00687_eXPressor_v1_4____CGSoftLabs_ {
  meta:
    description = "[eXPressor v1.4 -> CGSoftLabs]"
    ep_only     = "false"

  strings:
    $a = "eXPr-v.1.4."

  condition:
    $a
}