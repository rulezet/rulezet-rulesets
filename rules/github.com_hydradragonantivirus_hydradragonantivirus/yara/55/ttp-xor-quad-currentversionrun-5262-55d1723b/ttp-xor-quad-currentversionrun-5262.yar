rule TTP_XOR_QUAD_CurrentVersionRun_5262 {
  strings:
    $key_5262 = { 01 0d [2] 25 03 [2] 0e 2f [2] 20 0d [2] 34 16 [2] 3b 0c [2] 25 11 [2] 27 10 [2] 3c 16 [2] 20 11 [2] 3c 3e }

  condition:
    any of them
}