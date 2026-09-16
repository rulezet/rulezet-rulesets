rule TTP_XOR_QUAD_CurrentVersionRun_98ee {
  strings:
    $key_98ee = { cb 81 [2] ef 8f [2] c4 a3 [2] ea 81 [2] fe 9a [2] f1 80 [2] ef 9d [2] ed 9c [2] f6 9a [2] ea 9d [2] f6 b2 }

  condition:
    any of them
}