rule PEiD_02485_VBOX_v4_3_MTE_ {
  meta:
    description = "[VBOX v4.3 MTE]"
    ep_only     = "true"

  strings:
    $a = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }

  condition:
    $a
}