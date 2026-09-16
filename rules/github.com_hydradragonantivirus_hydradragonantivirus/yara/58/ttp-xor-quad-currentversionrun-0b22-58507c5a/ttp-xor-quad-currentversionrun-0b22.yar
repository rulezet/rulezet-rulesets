rule TTP_XOR_QUAD_CurrentVersionRun_0b22 {
  strings:
    $key_0b22 = { 58 4d [2] 7c 43 [2] 57 6f [2] 79 4d [2] 6d 56 [2] 62 4c [2] 7c 51 [2] 7e 50 [2] 65 56 [2] 79 51 [2] 65 7e }

  condition:
    any of them
}