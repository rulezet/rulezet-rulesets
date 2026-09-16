rule TTP_XOR_QUAD_CurrentVersionRun_9810 {
  strings:
    $key_9810 = { cb 7f [2] ef 71 [2] c4 5d [2] ea 7f [2] fe 64 [2] f1 7e [2] ef 63 [2] ed 62 [2] f6 64 [2] ea 63 [2] f6 4c }

  condition:
    any of them
}