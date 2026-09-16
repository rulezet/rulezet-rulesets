rule TTP_XOR_QUAD_CurrentVersionRun_9a7e {
  strings:
    $key_9a7e = { c9 11 [2] ed 1f [2] c6 33 [2] e8 11 [2] fc 0a [2] f3 10 [2] ed 0d [2] ef 0c [2] f4 0a [2] e8 0d [2] f4 22 }

  condition:
    any of them
}