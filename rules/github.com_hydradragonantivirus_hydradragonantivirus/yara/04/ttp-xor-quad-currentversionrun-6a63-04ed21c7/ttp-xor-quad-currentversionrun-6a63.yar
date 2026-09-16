rule TTP_XOR_QUAD_CurrentVersionRun_6a63 {
  strings:
    $key_6a63 = { 39 0c [2] 1d 02 [2] 36 2e [2] 18 0c [2] 0c 17 [2] 03 0d [2] 1d 10 [2] 1f 11 [2] 04 17 [2] 18 10 [2] 04 3f }

  condition:
    any of them
}