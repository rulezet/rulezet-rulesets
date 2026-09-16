rule TTP_XOR_QUAD_CurrentVersionRun_6e71 {
  strings:
    $key_6e71 = { 3d 1e [2] 19 10 [2] 32 3c [2] 1c 1e [2] 08 05 [2] 07 1f [2] 19 02 [2] 1b 03 [2] 00 05 [2] 1c 02 [2] 00 2d }

  condition:
    any of them
}