rule TTP_XOR_QUAD_CurrentVersionRun_e452 {
  strings:
    $key_e452 = { b7 3d [2] 93 33 [2] b8 1f [2] 96 3d [2] 82 26 [2] 8d 3c [2] 93 21 [2] 91 20 [2] 8a 26 [2] 96 21 [2] 8a 0e }

  condition:
    any of them
}