rule PEiD_01946_REC_v0_34__3_ {
  meta:
    description = "[REC v0.34 [3]"
    ep_only     = "true"

  strings:
    $a = { 06 1E B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }

  condition:
    $a
}