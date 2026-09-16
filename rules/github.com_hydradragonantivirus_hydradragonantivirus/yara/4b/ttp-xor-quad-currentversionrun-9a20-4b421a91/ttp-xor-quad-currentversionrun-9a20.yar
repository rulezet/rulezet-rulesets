rule TTP_XOR_QUAD_CurrentVersionRun_9a20 {
  strings:
    $key_9a20 = { c9 4f [2] ed 41 [2] c6 6d [2] e8 4f [2] fc 54 [2] f3 4e [2] ed 53 [2] ef 52 [2] f4 54 [2] e8 53 [2] f4 7c }

  condition:
    any of them
}