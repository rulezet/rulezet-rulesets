rule TTP_XOR_QUAD_CurrentVersionRun_eecd {
  strings:
    $key_eecd = { bd a2 [2] 99 ac [2] b2 80 [2] 9c a2 [2] 88 b9 [2] 87 a3 [2] 99 be [2] 9b bf [2] 80 b9 [2] 9c be [2] 80 91 }

  condition:
    any of them
}