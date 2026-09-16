rule TTP_XOR_QUAD_CurrentVersionRun_6aed {
  strings:
    $key_6aed = { 39 82 [2] 1d 8c [2] 36 a0 [2] 18 82 [2] 0c 99 [2] 03 83 [2] 1d 9e [2] 1f 9f [2] 04 99 [2] 18 9e [2] 04 b1 }

  condition:
    any of them
}