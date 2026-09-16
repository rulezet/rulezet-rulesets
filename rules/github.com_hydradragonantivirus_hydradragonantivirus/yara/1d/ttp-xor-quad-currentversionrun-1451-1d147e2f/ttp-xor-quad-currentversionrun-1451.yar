rule TTP_XOR_QUAD_CurrentVersionRun_1451 {
  strings:
    $key_1451 = { 47 3e [2] 63 30 [2] 48 1c [2] 66 3e [2] 72 25 [2] 7d 3f [2] 63 22 [2] 61 23 [2] 7a 25 [2] 66 22 [2] 7a 0d }

  condition:
    any of them
}