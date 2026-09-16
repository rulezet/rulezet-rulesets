rule TTP_XOR_QUAD_CurrentVersionRun_54e2 {
  strings:
    $key_54e2 = { 07 8d [2] 23 83 [2] 08 af [2] 26 8d [2] 32 96 [2] 3d 8c [2] 23 91 [2] 21 90 [2] 3a 96 [2] 26 91 [2] 3a be }

  condition:
    any of them
}