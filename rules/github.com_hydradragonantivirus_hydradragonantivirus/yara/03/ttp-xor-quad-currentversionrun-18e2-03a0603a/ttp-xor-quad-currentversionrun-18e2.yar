rule TTP_XOR_QUAD_CurrentVersionRun_18e2 {
  strings:
    $key_18e2 = { 4b 8d [2] 6f 83 [2] 44 af [2] 6a 8d [2] 7e 96 [2] 71 8c [2] 6f 91 [2] 6d 90 [2] 76 96 [2] 6a 91 [2] 76 be }

  condition:
    any of them
}