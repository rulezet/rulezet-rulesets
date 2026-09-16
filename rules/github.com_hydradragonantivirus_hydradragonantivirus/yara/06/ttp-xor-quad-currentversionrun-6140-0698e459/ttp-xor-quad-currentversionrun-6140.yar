rule TTP_XOR_QUAD_CurrentVersionRun_6140 {
  strings:
    $key_6140 = { 32 2f [2] 16 21 [2] 3d 0d [2] 13 2f [2] 07 34 [2] 08 2e [2] 16 33 [2] 14 32 [2] 0f 34 [2] 13 33 [2] 0f 1c }

  condition:
    any of them
}