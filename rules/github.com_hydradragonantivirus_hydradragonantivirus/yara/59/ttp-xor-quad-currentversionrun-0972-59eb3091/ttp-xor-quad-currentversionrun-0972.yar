rule TTP_XOR_QUAD_CurrentVersionRun_0972 {
  strings:
    $key_0972 = { 5a 1d [2] 7e 13 [2] 55 3f [2] 7b 1d [2] 6f 06 [2] 60 1c [2] 7e 01 [2] 7c 00 [2] 67 06 [2] 7b 01 [2] 67 2e }

  condition:
    any of them
}