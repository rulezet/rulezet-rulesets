rule TTP_XOR_QUAD_CurrentVersionRun_980e {
  strings:
    $key_980e = { cb 61 [2] ef 6f [2] c4 43 [2] ea 61 [2] fe 7a [2] f1 60 [2] ef 7d [2] ed 7c [2] f6 7a [2] ea 7d [2] f6 52 }

  condition:
    any of them
}