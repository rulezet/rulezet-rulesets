rule TTP_XOR_QUAD_CurrentVersionRun_1656 {
  strings:
    $key_1656 = { 45 39 [2] 61 37 [2] 4a 1b [2] 64 39 [2] 70 22 [2] 7f 38 [2] 61 25 [2] 63 24 [2] 78 22 [2] 64 25 [2] 78 0a }

  condition:
    any of them
}