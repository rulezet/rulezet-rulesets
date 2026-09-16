rule TTP_XOR_QUAD_CurrentVersionRun_1d26 {
  strings:
    $key_1d26 = { 4e 49 [2] 6a 47 [2] 41 6b [2] 6f 49 [2] 7b 52 [2] 74 48 [2] 6a 55 [2] 68 54 [2] 73 52 [2] 6f 55 [2] 73 7a }

  condition:
    any of them
}