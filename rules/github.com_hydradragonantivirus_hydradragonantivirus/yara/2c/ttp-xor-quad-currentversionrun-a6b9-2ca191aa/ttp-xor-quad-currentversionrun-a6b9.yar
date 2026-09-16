rule TTP_XOR_QUAD_CurrentVersionRun_a6b9 {
  strings:
    $key_a6b9 = { f5 d6 [2] d1 d8 [2] fa f4 [2] d4 d6 [2] c0 cd [2] cf d7 [2] d1 ca [2] d3 cb [2] c8 cd [2] d4 ca [2] c8 e5 }

  condition:
    any of them
}