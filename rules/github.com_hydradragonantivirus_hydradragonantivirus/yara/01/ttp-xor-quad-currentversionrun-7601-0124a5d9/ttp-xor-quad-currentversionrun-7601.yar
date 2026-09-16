rule TTP_XOR_QUAD_CurrentVersionRun_7601 {
  strings:
    $key_7601 = { 25 6e [2] 01 60 [2] 2a 4c [2] 04 6e [2] 10 75 [2] 1f 6f [2] 01 72 [2] 03 73 [2] 18 75 [2] 04 72 [2] 18 5d }

  condition:
    any of them
}