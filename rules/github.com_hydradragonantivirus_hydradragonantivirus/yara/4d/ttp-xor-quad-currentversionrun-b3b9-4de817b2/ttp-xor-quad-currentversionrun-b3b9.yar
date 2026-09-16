rule TTP_XOR_QUAD_CurrentVersionRun_b3b9 {
  strings:
    $key_b3b9 = { e0 d6 [2] c4 d8 [2] ef f4 [2] c1 d6 [2] d5 cd [2] da d7 [2] c4 ca [2] c6 cb [2] dd cd [2] c1 ca [2] dd e5 }

  condition:
    any of them
}