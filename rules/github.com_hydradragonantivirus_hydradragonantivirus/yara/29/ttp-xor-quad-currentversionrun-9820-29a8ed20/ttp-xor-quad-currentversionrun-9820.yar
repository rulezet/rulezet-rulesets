rule TTP_XOR_QUAD_CurrentVersionRun_9820 {
  strings:
    $key_9820 = { cb 4f [2] ef 41 [2] c4 6d [2] ea 4f [2] fe 54 [2] f1 4e [2] ef 53 [2] ed 52 [2] f6 54 [2] ea 53 [2] f6 7c }

  condition:
    any of them
}