rule TTP_XOR_QUAD_CurrentVersionRun_67e2 {
  strings:
    $key_67e2 = { 34 8d [2] 10 83 [2] 3b af [2] 15 8d [2] 01 96 [2] 0e 8c [2] 10 91 [2] 12 90 [2] 09 96 [2] 15 91 [2] 09 be }

  condition:
    any of them
}