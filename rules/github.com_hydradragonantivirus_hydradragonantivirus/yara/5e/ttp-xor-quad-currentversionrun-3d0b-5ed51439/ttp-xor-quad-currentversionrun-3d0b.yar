rule TTP_XOR_QUAD_CurrentVersionRun_3d0b {
  strings:
    $key_3d0b = { 6e 64 [2] 4a 6a [2] 61 46 [2] 4f 64 [2] 5b 7f [2] 54 65 [2] 4a 78 [2] 48 79 [2] 53 7f [2] 4f 78 [2] 53 57 }

  condition:
    any of them
}