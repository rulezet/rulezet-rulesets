rule TTP_XOR_QUAD_CurrentVersionRun_48e2 {
  strings:
    $key_48e2 = { 1b 8d [2] 3f 83 [2] 14 af [2] 3a 8d [2] 2e 96 [2] 21 8c [2] 3f 91 [2] 3d 90 [2] 26 96 [2] 3a 91 [2] 26 be }

  condition:
    any of them
}