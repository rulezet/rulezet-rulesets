rule TTP_XOR_QUAD_CurrentVersionRun_985d {
  strings:
    $key_985d = { cb 32 [2] ef 3c [2] c4 10 [2] ea 32 [2] fe 29 [2] f1 33 [2] ef 2e [2] ed 2f [2] f6 29 [2] ea 2e [2] f6 01 }

  condition:
    any of them
}