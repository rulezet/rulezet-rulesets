rule TTP_XOR_QUAD_CurrentVersionRun_4842 {
  strings:
    $key_4842 = { 1b 2d [2] 3f 23 [2] 14 0f [2] 3a 2d [2] 2e 36 [2] 21 2c [2] 3f 31 [2] 3d 30 [2] 26 36 [2] 3a 31 [2] 26 1e }

  condition:
    any of them
}