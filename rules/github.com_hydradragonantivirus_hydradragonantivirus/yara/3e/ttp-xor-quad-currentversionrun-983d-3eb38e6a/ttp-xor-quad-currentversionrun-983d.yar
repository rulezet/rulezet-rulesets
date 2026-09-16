rule TTP_XOR_QUAD_CurrentVersionRun_983d {
  strings:
    $key_983d = { cb 52 [2] ef 5c [2] c4 70 [2] ea 52 [2] fe 49 [2] f1 53 [2] ef 4e [2] ed 4f [2] f6 49 [2] ea 4e [2] f6 61 }

  condition:
    any of them
}