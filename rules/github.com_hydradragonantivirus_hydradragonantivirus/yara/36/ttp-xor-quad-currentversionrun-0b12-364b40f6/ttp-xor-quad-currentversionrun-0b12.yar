rule TTP_XOR_QUAD_CurrentVersionRun_0b12 {
  strings:
    $key_0b12 = { 58 7d [2] 7c 73 [2] 57 5f [2] 79 7d [2] 6d 66 [2] 62 7c [2] 7c 61 [2] 7e 60 [2] 65 66 [2] 79 61 [2] 65 4e }

  condition:
    any of them
}