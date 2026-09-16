rule TTP_XOR_QUAD_CurrentVersionRun_9a0d {
  strings:
    $key_9a0d = { c9 62 [2] ed 6c [2] c6 40 [2] e8 62 [2] fc 79 [2] f3 63 [2] ed 7e [2] ef 7f [2] f4 79 [2] e8 7e [2] f4 51 }

  condition:
    any of them
}