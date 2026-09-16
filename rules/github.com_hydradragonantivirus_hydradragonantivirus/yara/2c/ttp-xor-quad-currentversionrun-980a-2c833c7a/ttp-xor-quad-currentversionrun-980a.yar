rule TTP_XOR_QUAD_CurrentVersionRun_980a {
  strings:
    $key_980a = { cb 65 [2] ef 6b [2] c4 47 [2] ea 65 [2] fe 7e [2] f1 64 [2] ef 79 [2] ed 78 [2] f6 7e [2] ea 79 [2] f6 56 }

  condition:
    any of them
}