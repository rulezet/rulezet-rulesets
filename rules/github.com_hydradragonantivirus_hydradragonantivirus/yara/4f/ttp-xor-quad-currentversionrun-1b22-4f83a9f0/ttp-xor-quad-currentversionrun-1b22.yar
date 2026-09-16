rule TTP_XOR_QUAD_CurrentVersionRun_1b22 {
  strings:
    $key_1b22 = { 48 4d [2] 6c 43 [2] 47 6f [2] 69 4d [2] 7d 56 [2] 72 4c [2] 6c 51 [2] 6e 50 [2] 75 56 [2] 69 51 [2] 75 7e }

  condition:
    any of them
}