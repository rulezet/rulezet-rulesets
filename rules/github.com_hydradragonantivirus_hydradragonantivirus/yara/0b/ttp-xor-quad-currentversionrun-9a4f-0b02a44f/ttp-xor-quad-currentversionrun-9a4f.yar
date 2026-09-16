rule TTP_XOR_QUAD_CurrentVersionRun_9a4f {
  strings:
    $key_9a4f = { c9 20 [2] ed 2e [2] c6 02 [2] e8 20 [2] fc 3b [2] f3 21 [2] ed 3c [2] ef 3d [2] f4 3b [2] e8 3c [2] f4 13 }

  condition:
    any of them
}