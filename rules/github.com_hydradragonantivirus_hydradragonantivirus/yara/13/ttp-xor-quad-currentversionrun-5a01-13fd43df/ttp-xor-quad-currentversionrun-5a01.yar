rule TTP_XOR_QUAD_CurrentVersionRun_5a01 {
  strings:
    $key_5a01 = { 09 6e [2] 2d 60 [2] 06 4c [2] 28 6e [2] 3c 75 [2] 33 6f [2] 2d 72 [2] 2f 73 [2] 34 75 [2] 28 72 [2] 34 5d }

  condition:
    any of them
}