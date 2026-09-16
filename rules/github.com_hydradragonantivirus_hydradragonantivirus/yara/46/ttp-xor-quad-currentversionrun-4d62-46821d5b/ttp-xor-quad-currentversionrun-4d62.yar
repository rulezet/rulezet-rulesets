rule TTP_XOR_QUAD_CurrentVersionRun_4d62 {
  strings:
    $key_4d62 = { 1e 0d [2] 3a 03 [2] 11 2f [2] 3f 0d [2] 2b 16 [2] 24 0c [2] 3a 11 [2] 38 10 [2] 23 16 [2] 3f 11 [2] 23 3e }

  condition:
    any of them
}