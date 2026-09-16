rule TTP_XOR_QUAD_CurrentVersionRun_46e2 {
  strings:
    $key_46e2 = { 15 8d [2] 31 83 [2] 1a af [2] 34 8d [2] 20 96 [2] 2f 8c [2] 31 91 [2] 33 90 [2] 28 96 [2] 34 91 [2] 28 be }

  condition:
    any of them
}