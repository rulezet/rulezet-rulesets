rule TTP_XOR_QUAD_CurrentVersionRun_1aac {
  strings:
    $key_1aac = { 49 c3 [2] 6d cd [2] 46 e1 [2] 68 c3 [2] 7c d8 [2] 73 c2 [2] 6d df [2] 6f de [2] 74 d8 [2] 68 df [2] 74 f0 }

  condition:
    any of them
}