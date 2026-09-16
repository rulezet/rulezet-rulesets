rule TTP_XOR_QUAD_CurrentVersionRun_6e40 {
  strings:
    $key_6e40 = { 3d 2f [2] 19 21 [2] 32 0d [2] 1c 2f [2] 08 34 [2] 07 2e [2] 19 33 [2] 1b 32 [2] 00 34 [2] 1c 33 [2] 00 1c }

  condition:
    any of them
}