rule TTP_XOR_QUAD_CurrentVersionRun_6af3 {
  strings:
    $key_6af3 = { 39 9c [2] 1d 92 [2] 36 be [2] 18 9c [2] 0c 87 [2] 03 9d [2] 1d 80 [2] 1f 81 [2] 04 87 [2] 18 80 [2] 04 af }

  condition:
    any of them
}