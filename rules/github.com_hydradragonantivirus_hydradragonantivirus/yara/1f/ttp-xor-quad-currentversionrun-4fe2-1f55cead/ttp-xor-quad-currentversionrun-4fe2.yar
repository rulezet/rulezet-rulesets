rule TTP_XOR_QUAD_CurrentVersionRun_4fe2 {
  strings:
    $key_4fe2 = { 1c 8d [2] 38 83 [2] 13 af [2] 3d 8d [2] 29 96 [2] 26 8c [2] 38 91 [2] 3a 90 [2] 21 96 [2] 3d 91 [2] 21 be }

  condition:
    any of them
}