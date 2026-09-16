rule TTP_XOR_QUAD_CurrentVersionRun_6e77 {
  strings:
    $key_6e77 = { 3d 18 [2] 19 16 [2] 32 3a [2] 1c 18 [2] 08 03 [2] 07 19 [2] 19 04 [2] 1b 05 [2] 00 03 [2] 1c 04 [2] 00 2b }

  condition:
    any of them
}