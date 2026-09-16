rule TTP_XOR_QUAD_CurrentVersionRun_d7b9 {
  strings:
    $key_d7b9 = { 84 d6 [2] a0 d8 [2] 8b f4 [2] a5 d6 [2] b1 cd [2] be d7 [2] a0 ca [2] a2 cb [2] b9 cd [2] a5 ca [2] b9 e5 }

  condition:
    any of them
}