rule TTP_XOR_QUAD_CurrentVersionRun_76e2 {
  strings:
    $key_76e2 = { 25 8d [2] 01 83 [2] 2a af [2] 04 8d [2] 10 96 [2] 1f 8c [2] 01 91 [2] 03 90 [2] 18 96 [2] 04 91 [2] 18 be }

  condition:
    any of them
}