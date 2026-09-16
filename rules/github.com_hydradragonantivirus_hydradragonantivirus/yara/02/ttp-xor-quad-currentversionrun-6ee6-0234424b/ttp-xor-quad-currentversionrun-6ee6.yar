rule TTP_XOR_QUAD_CurrentVersionRun_6ee6 {
  strings:
    $key_6ee6 = { 3d 89 [2] 19 87 [2] 32 ab [2] 1c 89 [2] 08 92 [2] 07 88 [2] 19 95 [2] 1b 94 [2] 00 92 [2] 1c 95 [2] 00 ba }

  condition:
    any of them
}