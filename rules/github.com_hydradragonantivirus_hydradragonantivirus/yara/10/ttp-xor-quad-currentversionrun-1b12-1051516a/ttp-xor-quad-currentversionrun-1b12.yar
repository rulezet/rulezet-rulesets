rule TTP_XOR_QUAD_CurrentVersionRun_1b12 {
  strings:
    $key_1b12 = { 48 7d [2] 6c 73 [2] 47 5f [2] 69 7d [2] 7d 66 [2] 72 7c [2] 6c 61 [2] 6e 60 [2] 75 66 [2] 69 61 [2] 75 4e }

  condition:
    any of them
}