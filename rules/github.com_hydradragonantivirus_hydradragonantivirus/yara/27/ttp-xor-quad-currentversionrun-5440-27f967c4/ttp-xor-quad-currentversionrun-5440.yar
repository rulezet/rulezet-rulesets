rule TTP_XOR_QUAD_CurrentVersionRun_5440 {
  strings:
    $key_5440 = { 07 2f [2] 23 21 [2] 08 0d [2] 26 2f [2] 32 34 [2] 3d 2e [2] 23 33 [2] 21 32 [2] 3a 34 [2] 26 33 [2] 3a 1c }

  condition:
    any of them
}