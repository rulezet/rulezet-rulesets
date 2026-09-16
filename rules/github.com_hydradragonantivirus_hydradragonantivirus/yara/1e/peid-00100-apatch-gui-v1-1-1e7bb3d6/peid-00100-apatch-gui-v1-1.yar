rule PEiD_00100_APatch_GUI_v1_1_ {
  meta:
    description = "[APatch GUI v1.1]"
    ep_only     = "true"

  strings:
    $a = { 52 31 C0 E8 FF FF FF FF }

  condition:
    $a
}