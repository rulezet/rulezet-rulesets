rule TTP_XOR_QUAD_CurrentVersionRun_47e2 {
  strings:
    $key_47e2 = { 14 8d [2] 30 83 [2] 1b af [2] 35 8d [2] 21 96 [2] 2e 8c [2] 30 91 [2] 32 90 [2] 29 96 [2] 35 91 [2] 29 be }

  condition:
    any of them
}