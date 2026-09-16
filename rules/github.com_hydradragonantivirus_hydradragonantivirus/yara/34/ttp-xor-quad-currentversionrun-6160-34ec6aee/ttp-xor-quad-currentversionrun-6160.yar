rule TTP_XOR_QUAD_CurrentVersionRun_6160 {
  strings:
    $key_6160 = { 32 0f [2] 16 01 [2] 3d 2d [2] 13 0f [2] 07 14 [2] 08 0e [2] 16 13 [2] 14 12 [2] 0f 14 [2] 13 13 [2] 0f 3c }

  condition:
    any of them
}