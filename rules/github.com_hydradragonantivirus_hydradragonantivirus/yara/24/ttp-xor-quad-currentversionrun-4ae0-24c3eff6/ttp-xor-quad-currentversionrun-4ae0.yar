rule TTP_XOR_QUAD_CurrentVersionRun_4ae0 {
  strings:
    $key_4ae0 = { 19 8f [2] 3d 81 [2] 16 ad [2] 38 8f [2] 2c 94 [2] 23 8e [2] 3d 93 [2] 3f 92 [2] 24 94 [2] 38 93 [2] 24 bc }

  condition:
    any of them
}