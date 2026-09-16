rule TTP_XOR_QUAD_CurrentVersionRun_2df7 {
  strings:
    $key_2df7 = { 7e 98 [2] 5a 96 [2] 71 ba [2] 5f 98 [2] 4b 83 [2] 44 99 [2] 5a 84 [2] 58 85 [2] 43 83 [2] 5f 84 [2] 43 ab }

  condition:
    any of them
}