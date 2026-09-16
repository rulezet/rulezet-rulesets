rule TTP_XOR_QUAD_CurrentVersionRun_42e2 {
  strings:
    $key_42e2 = { 11 8d [2] 35 83 [2] 1e af [2] 30 8d [2] 24 96 [2] 2b 8c [2] 35 91 [2] 37 90 [2] 2c 96 [2] 30 91 [2] 2c be }

  condition:
    any of them
}