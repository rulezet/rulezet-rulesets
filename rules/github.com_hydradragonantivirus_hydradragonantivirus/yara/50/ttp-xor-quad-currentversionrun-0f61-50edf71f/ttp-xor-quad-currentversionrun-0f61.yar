rule TTP_XOR_QUAD_CurrentVersionRun_0f61 {
  strings:
    $key_0f61 = { 5c 0e [2] 78 00 [2] 53 2c [2] 7d 0e [2] 69 15 [2] 66 0f [2] 78 12 [2] 7a 13 [2] 61 15 [2] 7d 12 [2] 61 3d }

  condition:
    any of them
}