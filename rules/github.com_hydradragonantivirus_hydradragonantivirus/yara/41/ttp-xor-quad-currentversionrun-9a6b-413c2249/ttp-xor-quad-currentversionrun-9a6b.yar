rule TTP_XOR_QUAD_CurrentVersionRun_9a6b {
  strings:
    $key_9a6b = { c9 04 [2] ed 0a [2] c6 26 [2] e8 04 [2] fc 1f [2] f3 05 [2] ed 18 [2] ef 19 [2] f4 1f [2] e8 18 [2] f4 37 }

  condition:
    any of them
}