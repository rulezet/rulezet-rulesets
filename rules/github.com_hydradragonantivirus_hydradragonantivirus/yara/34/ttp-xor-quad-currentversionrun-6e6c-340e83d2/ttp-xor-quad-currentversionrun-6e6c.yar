rule TTP_XOR_QUAD_CurrentVersionRun_6e6c {
  strings:
    $key_6e6c = { 3d 03 [2] 19 0d [2] 32 21 [2] 1c 03 [2] 08 18 [2] 07 02 [2] 19 1f [2] 1b 1e [2] 00 18 [2] 1c 1f [2] 00 30 }

  condition:
    any of them
}