rule TTP_XOR_QUAD_CurrentVersionRun_9afb {
  strings:
    $key_9afb = { c9 94 [2] ed 9a [2] c6 b6 [2] e8 94 [2] fc 8f [2] f3 95 [2] ed 88 [2] ef 89 [2] f4 8f [2] e8 88 [2] f4 a7 }

  condition:
    any of them
}