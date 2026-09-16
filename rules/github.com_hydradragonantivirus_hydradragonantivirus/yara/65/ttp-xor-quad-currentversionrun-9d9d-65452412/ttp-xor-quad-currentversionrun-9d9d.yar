rule TTP_XOR_QUAD_CurrentVersionRun_9d9d {
  strings:
    $key_9d9d = { ce f2 [2] ea fc [2] c1 d0 [2] ef f2 [2] fb e9 [2] f4 f3 [2] ea ee [2] e8 ef [2] f3 e9 [2] ef ee [2] f3 c1 }

  condition:
    any of them
}