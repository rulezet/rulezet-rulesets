rule TTP_XOR_QUAD_CurrentVersionRun_1263 {
  strings:
    $key_1263 = { 41 0c [2] 65 02 [2] 4e 2e [2] 60 0c [2] 74 17 [2] 7b 0d [2] 65 10 [2] 67 11 [2] 7c 17 [2] 60 10 [2] 7c 3f }

  condition:
    any of them
}