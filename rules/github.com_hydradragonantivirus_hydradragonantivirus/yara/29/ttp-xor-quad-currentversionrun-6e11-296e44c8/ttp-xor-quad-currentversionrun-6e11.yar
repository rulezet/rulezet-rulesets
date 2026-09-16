rule TTP_XOR_QUAD_CurrentVersionRun_6e11 {
  strings:
    $key_6e11 = { 3d 7e [2] 19 70 [2] 32 5c [2] 1c 7e [2] 08 65 [2] 07 7f [2] 19 62 [2] 1b 63 [2] 00 65 [2] 1c 62 [2] 00 4d }

  condition:
    any of them
}