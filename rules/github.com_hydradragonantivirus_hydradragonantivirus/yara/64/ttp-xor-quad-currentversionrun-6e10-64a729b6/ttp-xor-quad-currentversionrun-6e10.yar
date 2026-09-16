rule TTP_XOR_QUAD_CurrentVersionRun_6e10 {
  strings:
    $key_6e10 = { 3d 7f [2] 19 71 [2] 32 5d [2] 1c 7f [2] 08 64 [2] 07 7e [2] 19 63 [2] 1b 62 [2] 00 64 [2] 1c 63 [2] 00 4c }

  condition:
    any of them
}