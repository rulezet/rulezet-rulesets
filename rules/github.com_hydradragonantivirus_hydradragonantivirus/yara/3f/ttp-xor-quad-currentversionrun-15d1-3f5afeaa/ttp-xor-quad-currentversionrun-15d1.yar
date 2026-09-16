rule TTP_XOR_QUAD_CurrentVersionRun_15d1 {
  strings:
    $key_15d1 = { 46 be [2] 62 b0 [2] 49 9c [2] 67 be [2] 73 a5 [2] 7c bf [2] 62 a2 [2] 60 a3 [2] 7b a5 [2] 67 a2 [2] 7b 8d }

  condition:
    any of them
}