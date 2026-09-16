rule TTP_XOR_QUAD_CurrentVersionRun_980c {
  strings:
    $key_980c = { cb 63 [2] ef 6d [2] c4 41 [2] ea 63 [2] fe 78 [2] f1 62 [2] ef 7f [2] ed 7e [2] f6 78 [2] ea 7f [2] f6 50 }

  condition:
    any of them
}