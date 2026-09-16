rule TTP_XOR_QUAD_CurrentVersionRun_e44e {
  strings:
    $key_e44e = { b7 21 [2] 93 2f [2] b8 03 [2] 96 21 [2] 82 3a [2] 8d 20 [2] 93 3d [2] 91 3c [2] 8a 3a [2] 96 3d [2] 8a 12 }

  condition:
    any of them
}