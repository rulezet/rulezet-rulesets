rule TTP_XOR_QUAD_CurrentVersionRun_0c26 {
  strings:
    $key_0c26 = { 5f 49 [2] 7b 47 [2] 50 6b [2] 7e 49 [2] 6a 52 [2] 65 48 [2] 7b 55 [2] 79 54 [2] 62 52 [2] 7e 55 [2] 62 7a }

  condition:
    any of them
}