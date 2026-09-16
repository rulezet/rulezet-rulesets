rule TTP_XOR_QUAD_CurrentVersionRun_9a1e {
  strings:
    $key_9a1e = { c9 71 [2] ed 7f [2] c6 53 [2] e8 71 [2] fc 6a [2] f3 70 [2] ed 6d [2] ef 6c [2] f4 6a [2] e8 6d [2] f4 42 }

  condition:
    any of them
}