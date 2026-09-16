rule TTP_XOR_QUAD_CurrentVersionRun_a9ab {
  strings:
    $key_a9ab = { fa c4 [2] de ca [2] f5 e6 [2] db c4 [2] cf df [2] c0 c5 [2] de d8 [2] dc d9 [2] c7 df [2] db d8 [2] c7 f7 }

  condition:
    any of them
}