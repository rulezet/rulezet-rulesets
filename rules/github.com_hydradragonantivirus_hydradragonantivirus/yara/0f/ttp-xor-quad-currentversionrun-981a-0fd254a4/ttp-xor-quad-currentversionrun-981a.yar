rule TTP_XOR_QUAD_CurrentVersionRun_981a {
  strings:
    $key_981a = { cb 75 [2] ef 7b [2] c4 57 [2] ea 75 [2] fe 6e [2] f1 74 [2] ef 69 [2] ed 68 [2] f6 6e [2] ea 69 [2] f6 46 }

  condition:
    any of them
}