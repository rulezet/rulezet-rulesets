rule TTP_XOR_QUAD_CurrentVersionRun_6151 {
  strings:
    $key_6151 = { 32 3e [2] 16 30 [2] 3d 1c [2] 13 3e [2] 07 25 [2] 08 3f [2] 16 22 [2] 14 23 [2] 0f 25 [2] 13 22 [2] 0f 0d }

  condition:
    any of them
}