rule TTP_XOR_QUAD_CurrentVersionRun_1441 {
  strings:
    $key_1441 = { 47 2e [2] 63 20 [2] 48 0c [2] 66 2e [2] 72 35 [2] 7d 2f [2] 63 32 [2] 61 33 [2] 7a 35 [2] 66 32 [2] 7a 1d }

  condition:
    any of them
}