rule TTP_XOR_QUAD_CurrentVersionRun_5bf1 {
  strings:
    $key_5bf1 = { 08 9e [2] 2c 90 [2] 07 bc [2] 29 9e [2] 3d 85 [2] 32 9f [2] 2c 82 [2] 2e 83 [2] 35 85 [2] 29 82 [2] 35 ad }

  condition:
    any of them
}