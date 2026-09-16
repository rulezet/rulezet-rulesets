rule TTP_XOR_QUAD_CurrentVersionRun_986a {
  strings:
    $key_986a = { cb 05 [2] ef 0b [2] c4 27 [2] ea 05 [2] fe 1e [2] f1 04 [2] ef 19 [2] ed 18 [2] f6 1e [2] ea 19 [2] f6 36 }

  condition:
    any of them
}