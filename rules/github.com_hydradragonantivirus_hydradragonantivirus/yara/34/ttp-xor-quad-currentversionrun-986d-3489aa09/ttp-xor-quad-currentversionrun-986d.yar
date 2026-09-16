rule TTP_XOR_QUAD_CurrentVersionRun_986d {
  strings:
    $key_986d = { cb 02 [2] ef 0c [2] c4 20 [2] ea 02 [2] fe 19 [2] f1 03 [2] ef 1e [2] ed 1f [2] f6 19 [2] ea 1e [2] f6 31 }

  condition:
    any of them
}