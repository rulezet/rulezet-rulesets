rule TTP_XOR_QUAD_CurrentVersionRun_d8cd {
  strings:
    $key_d8cd = { 8b a2 [2] af ac [2] 84 80 [2] aa a2 [2] be b9 [2] b1 a3 [2] af be [2] ad bf [2] b6 b9 [2] aa be [2] b6 91 }

  condition:
    any of them
}