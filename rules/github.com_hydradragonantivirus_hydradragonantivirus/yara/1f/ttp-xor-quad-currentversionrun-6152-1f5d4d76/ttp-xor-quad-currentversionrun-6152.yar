rule TTP_XOR_QUAD_CurrentVersionRun_6152 {
  strings:
    $key_6152 = { 32 3d [2] 16 33 [2] 3d 1f [2] 13 3d [2] 07 26 [2] 08 3c [2] 16 21 [2] 14 20 [2] 0f 26 [2] 13 21 [2] 0f 0e }

  condition:
    any of them
}