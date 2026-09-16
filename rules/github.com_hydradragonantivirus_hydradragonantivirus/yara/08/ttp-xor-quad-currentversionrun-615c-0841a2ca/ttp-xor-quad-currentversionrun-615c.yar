rule TTP_XOR_QUAD_CurrentVersionRun_615c {
  strings:
    $key_615c = { 32 33 [2] 16 3d [2] 3d 11 [2] 13 33 [2] 07 28 [2] 08 32 [2] 16 2f [2] 14 2e [2] 0f 28 [2] 13 2f [2] 0f 00 }

  condition:
    any of them
}