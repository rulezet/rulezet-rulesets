rule TTP_XOR_QUAD_CurrentVersionRun_985a {
  strings:
    $key_985a = { cb 35 [2] ef 3b [2] c4 17 [2] ea 35 [2] fe 2e [2] f1 34 [2] ef 29 [2] ed 28 [2] f6 2e [2] ea 29 [2] f6 06 }

  condition:
    any of them
}