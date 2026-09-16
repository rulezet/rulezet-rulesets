rule TTP_XOR_QUAD_CurrentVersionRun_e5ab {
  strings:
    $key_e5ab = { b6 c4 [2] 92 ca [2] b9 e6 [2] 97 c4 [2] 83 df [2] 8c c5 [2] 92 d8 [2] 90 d9 [2] 8b df [2] 97 d8 [2] 8b f7 }

  condition:
    any of them
}