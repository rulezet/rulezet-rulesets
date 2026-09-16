rule TTP_XOR_QUAD_CurrentVersionRun_e2b9 {
  strings:
    $key_e2b9 = { b1 d6 [2] 95 d8 [2] be f4 [2] 90 d6 [2] 84 cd [2] 8b d7 [2] 95 ca [2] 97 cb [2] 8c cd [2] 90 ca [2] 8c e5 }

  condition:
    any of them
}