rule PEiD_02481_VBOX_v4_2_MTE_ {
  meta:
    description = "[VBOX v4.2 MTE]"
    ep_only     = "true"

  strings:
    $a = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }

  condition:
    $a
}