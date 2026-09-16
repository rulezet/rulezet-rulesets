rule TTP_XOR_QUAD_CurrentVersionRun_25ab {
  strings:
    $key_25ab = { 76 c4 [2] 52 ca [2] 79 e6 [2] 57 c4 [2] 43 df [2] 4c c5 [2] 52 d8 [2] 50 d9 [2] 4b df [2] 57 d8 [2] 4b f7 }

  condition:
    any of them
}