rule TTP_XOR_QUAD_CurrentVersionRun_6b63 {
  strings:
    $key_6b63 = { 38 0c [2] 1c 02 [2] 37 2e [2] 19 0c [2] 0d 17 [2] 02 0d [2] 1c 10 [2] 1e 11 [2] 05 17 [2] 19 10 [2] 05 3f }

  condition:
    any of them
}