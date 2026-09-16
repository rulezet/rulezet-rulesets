rule TTP_XOR_QUAD_CurrentVersionRun_6aac {
  strings:
    $key_6aac = { 39 c3 [2] 1d cd [2] 36 e1 [2] 18 c3 [2] 0c d8 [2] 03 c2 [2] 1d df [2] 1f de [2] 04 d8 [2] 18 df [2] 04 f0 }

  condition:
    any of them
}