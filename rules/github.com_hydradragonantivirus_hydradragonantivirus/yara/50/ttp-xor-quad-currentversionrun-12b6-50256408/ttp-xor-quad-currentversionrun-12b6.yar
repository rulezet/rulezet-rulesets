rule TTP_XOR_QUAD_CurrentVersionRun_12b6 {
  strings:
    $key_12b6 = { 41 d9 [2] 65 d7 [2] 4e fb [2] 60 d9 [2] 74 c2 [2] 7b d8 [2] 65 c5 [2] 67 c4 [2] 7c c2 [2] 60 c5 [2] 7c ea }

  condition:
    any of them
}