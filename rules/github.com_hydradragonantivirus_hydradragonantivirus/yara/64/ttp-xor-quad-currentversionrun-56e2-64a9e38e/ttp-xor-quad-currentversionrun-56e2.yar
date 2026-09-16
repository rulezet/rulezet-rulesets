rule TTP_XOR_QUAD_CurrentVersionRun_56e2 {
  strings:
    $key_56e2 = { 05 8d [2] 21 83 [2] 0a af [2] 24 8d [2] 30 96 [2] 3f 8c [2] 21 91 [2] 23 90 [2] 38 96 [2] 24 91 [2] 38 be }

  condition:
    any of them
}