rule TTP_XOR_QUAD_CurrentVersionRun_15ab {
  strings:
    $key_15ab = { 46 c4 [2] 62 ca [2] 49 e6 [2] 67 c4 [2] 73 df [2] 7c c5 [2] 62 d8 [2] 60 d9 [2] 7b df [2] 67 d8 [2] 7b f7 }

  condition:
    any of them
}