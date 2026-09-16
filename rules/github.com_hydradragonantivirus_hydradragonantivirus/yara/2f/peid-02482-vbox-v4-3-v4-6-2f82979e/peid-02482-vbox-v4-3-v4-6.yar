rule PEiD_02482_VBOX_v4_3___v4_6_ {
  meta:
    description = "[VBOX v4.3 - v4.6]"
    ep_only     = "false"

  strings:
    $a = { 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 }

  condition:
    $a
}