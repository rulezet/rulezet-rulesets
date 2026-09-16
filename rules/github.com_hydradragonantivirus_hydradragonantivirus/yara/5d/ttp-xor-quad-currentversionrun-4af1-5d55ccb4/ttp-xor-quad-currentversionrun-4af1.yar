rule TTP_XOR_QUAD_CurrentVersionRun_4af1 {
  strings:
    $key_4af1 = { 19 9e [2] 3d 90 [2] 16 bc [2] 38 9e [2] 2c 85 [2] 23 9f [2] 3d 82 [2] 3f 83 [2] 24 85 [2] 38 82 [2] 24 ad }

  condition:
    any of them
}