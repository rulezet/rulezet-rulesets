rule TTP_XOR_QUAD_CurrentVersionRun_980d {
  strings:
    $key_980d = { cb 62 [2] ef 6c [2] c4 40 [2] ea 62 [2] fe 79 [2] f1 63 [2] ef 7e [2] ed 7f [2] f6 79 [2] ea 7e [2] f6 51 }

  condition:
    any of them
}