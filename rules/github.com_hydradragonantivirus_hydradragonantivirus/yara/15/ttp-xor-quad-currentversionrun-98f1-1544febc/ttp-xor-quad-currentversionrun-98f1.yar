rule TTP_XOR_QUAD_CurrentVersionRun_98f1 {
  strings:
    $key_98f1 = { cb 9e [2] ef 90 [2] c4 bc [2] ea 9e [2] fe 85 [2] f1 9f [2] ef 82 [2] ed 83 [2] f6 85 [2] ea 82 [2] f6 ad }

  condition:
    any of them
}