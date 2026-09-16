rule TTP_XOR_QUAD_CurrentVersionRun_984a {
  strings:
    $key_984a = { cb 25 [2] ef 2b [2] c4 07 [2] ea 25 [2] fe 3e [2] f1 24 [2] ef 39 [2] ed 38 [2] f6 3e [2] ea 39 [2] f6 16 }

  condition:
    any of them
}