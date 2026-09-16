rule TTP_XOR_QUAD_CurrentVersionRun_4a3b {
  strings:
    $key_4a3b = { 19 54 [2] 3d 5a [2] 16 76 [2] 38 54 [2] 2c 4f [2] 23 55 [2] 3d 48 [2] 3f 49 [2] 24 4f [2] 38 48 [2] 24 67 }

  condition:
    any of them
}