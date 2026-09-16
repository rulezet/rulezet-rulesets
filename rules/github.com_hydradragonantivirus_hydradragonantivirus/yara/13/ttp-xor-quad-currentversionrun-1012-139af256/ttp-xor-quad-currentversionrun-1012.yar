rule TTP_XOR_QUAD_CurrentVersionRun_1012 {
  strings:
    $key_1012 = { 43 7d [2] 67 73 [2] 4c 5f [2] 62 7d [2] 76 66 [2] 79 7c [2] 67 61 [2] 65 60 [2] 7e 66 [2] 62 61 [2] 7e 4e }

  condition:
    any of them
}