rule TTP_XOR_QUAD_CurrentVersionRun_4ace {
  strings:
    $key_4ace = { 19 a1 [2] 3d af [2] 16 83 [2] 38 a1 [2] 2c ba [2] 23 a0 [2] 3d bd [2] 3f bc [2] 24 ba [2] 38 bd [2] 24 92 }

  condition:
    any of them
}