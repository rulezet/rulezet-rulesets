rule TTP_XOR_QUAD_CurrentVersionRun_98e0 {
  strings:
    $key_98e0 = { cb 8f [2] ef 81 [2] c4 ad [2] ea 8f [2] fe 94 [2] f1 8e [2] ef 93 [2] ed 92 [2] f6 94 [2] ea 93 [2] f6 bc }

  condition:
    any of them
}