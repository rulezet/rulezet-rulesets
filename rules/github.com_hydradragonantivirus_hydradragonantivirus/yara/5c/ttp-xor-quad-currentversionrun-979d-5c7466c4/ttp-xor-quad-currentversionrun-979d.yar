rule TTP_XOR_QUAD_CurrentVersionRun_979d {
  strings:
    $key_979d = { c4 f2 [2] e0 fc [2] cb d0 [2] e5 f2 [2] f1 e9 [2] fe f3 [2] e0 ee [2] e2 ef [2] f9 e9 [2] e5 ee [2] f9 c1 }

  condition:
    any of them
}