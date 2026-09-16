rule TTP_XOR_QUAD_CurrentVersionRun_2df1 {
  strings:
    $key_2df1 = { 7e 9e [2] 5a 90 [2] 71 bc [2] 5f 9e [2] 4b 85 [2] 44 9f [2] 5a 82 [2] 58 83 [2] 43 85 [2] 5f 82 [2] 43 ad }

  condition:
    any of them
}