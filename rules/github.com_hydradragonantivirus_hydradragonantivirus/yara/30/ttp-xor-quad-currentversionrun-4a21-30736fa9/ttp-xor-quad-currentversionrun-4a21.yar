rule TTP_XOR_QUAD_CurrentVersionRun_4a21 {
  strings:
    $key_4a21 = { 19 4e [2] 3d 40 [2] 16 6c [2] 38 4e [2] 2c 55 [2] 23 4f [2] 3d 52 [2] 3f 53 [2] 24 55 [2] 38 52 [2] 24 7d }

  condition:
    any of them
}