rule TTP_XOR_QUAD_CurrentVersionRun_a9be {
  strings:
    $key_a9be = { fa d1 [2] de df [2] f5 f3 [2] db d1 [2] cf ca [2] c0 d0 [2] de cd [2] dc cc [2] c7 ca [2] db cd [2] c7 e2 }

  condition:
    any of them
}