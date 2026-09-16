rule TTP_XOR_QUAD_CurrentVersionRun_953c {
  strings:
    $key_953c = { c6 53 [2] e2 5d [2] c9 71 [2] e7 53 [2] f3 48 [2] fc 52 [2] e2 4f [2] e0 4e [2] fb 48 [2] e7 4f [2] fb 60 }

  condition:
    any of them
}