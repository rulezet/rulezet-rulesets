rule TTP_XOR_QUAD_CurrentVersionRun_32b6 {
  strings:
    $key_32b6 = { 61 d9 [2] 45 d7 [2] 6e fb [2] 40 d9 [2] 54 c2 [2] 5b d8 [2] 45 c5 [2] 47 c4 [2] 5c c2 [2] 40 c5 [2] 5c ea }

  condition:
    any of them
}