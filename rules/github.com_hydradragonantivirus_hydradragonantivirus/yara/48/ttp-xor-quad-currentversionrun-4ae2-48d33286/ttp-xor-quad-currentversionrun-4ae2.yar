rule TTP_XOR_QUAD_CurrentVersionRun_4ae2 {
  strings:
    $key_4ae2 = { 19 8d [2] 3d 83 [2] 16 af [2] 38 8d [2] 2c 96 [2] 23 8c [2] 3d 91 [2] 3f 90 [2] 24 96 [2] 38 91 [2] 24 be }

  condition:
    any of them
}