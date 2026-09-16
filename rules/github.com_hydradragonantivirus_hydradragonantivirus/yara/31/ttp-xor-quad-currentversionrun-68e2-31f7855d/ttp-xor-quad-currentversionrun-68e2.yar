rule TTP_XOR_QUAD_CurrentVersionRun_68e2 {
  strings:
    $key_68e2 = { 3b 8d [2] 1f 83 [2] 34 af [2] 1a 8d [2] 0e 96 [2] 01 8c [2] 1f 91 [2] 1d 90 [2] 06 96 [2] 1a 91 [2] 06 be }

  condition:
    any of them
}