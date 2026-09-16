rule TTP_XOR_QUAD_CurrentVersionRun_b5b9 {
  strings:
    $key_b5b9 = { e6 d6 [2] c2 d8 [2] e9 f4 [2] c7 d6 [2] d3 cd [2] dc d7 [2] c2 ca [2] c0 cb [2] db cd [2] c7 ca [2] db e5 }

  condition:
    any of them
}