rule TTP_XOR_QUAD_CurrentVersionRun_5d62 {
  strings:
    $key_5d62 = { 0e 0d [2] 2a 03 [2] 01 2f [2] 2f 0d [2] 3b 16 [2] 34 0c [2] 2a 11 [2] 28 10 [2] 33 16 [2] 2f 11 [2] 33 3e }

  condition:
    any of them
}