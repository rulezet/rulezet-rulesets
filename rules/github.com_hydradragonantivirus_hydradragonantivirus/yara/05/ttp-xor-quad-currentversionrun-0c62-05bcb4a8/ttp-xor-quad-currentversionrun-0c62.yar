rule TTP_XOR_QUAD_CurrentVersionRun_0c62 {
  strings:
    $key_0c62 = { 5f 0d [2] 7b 03 [2] 50 2f [2] 7e 0d [2] 6a 16 [2] 65 0c [2] 7b 11 [2] 79 10 [2] 62 16 [2] 7e 11 [2] 62 3e }

  condition:
    any of them
}