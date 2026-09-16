rule TTP_XOR_QUAD_CurrentVersionRun_4612 {
  strings:
    $key_4612 = { 15 7d [2] 31 73 [2] 1a 5f [2] 34 7d [2] 20 66 [2] 2f 7c [2] 31 61 [2] 33 60 [2] 28 66 [2] 34 61 [2] 28 4e }

  condition:
    any of them
}