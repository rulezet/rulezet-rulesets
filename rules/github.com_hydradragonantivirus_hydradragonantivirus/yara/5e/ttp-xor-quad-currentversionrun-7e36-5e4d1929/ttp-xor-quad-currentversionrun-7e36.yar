rule TTP_XOR_QUAD_CurrentVersionRun_7e36 {
  strings:
    $key_7e36 = { 2d 59 [2] 09 57 [2] 22 7b [2] 0c 59 [2] 18 42 [2] 17 58 [2] 09 45 [2] 0b 44 [2] 10 42 [2] 0c 45 [2] 10 6a }

  condition:
    any of them
}