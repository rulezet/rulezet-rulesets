rule TTP_XOR_QUAD_CurrentVersionRun_0862 {
  strings:
    $key_0862 = { 5b 0d [2] 7f 03 [2] 54 2f [2] 7a 0d [2] 6e 16 [2] 61 0c [2] 7f 11 [2] 7d 10 [2] 66 16 [2] 7a 11 [2] 66 3e }

  condition:
    any of them
}