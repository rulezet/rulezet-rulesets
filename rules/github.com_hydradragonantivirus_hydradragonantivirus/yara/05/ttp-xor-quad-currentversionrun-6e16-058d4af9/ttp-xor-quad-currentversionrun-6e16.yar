rule TTP_XOR_QUAD_CurrentVersionRun_6e16 {
  strings:
    $key_6e16 = { 3d 79 [2] 19 77 [2] 32 5b [2] 1c 79 [2] 08 62 [2] 07 78 [2] 19 65 [2] 1b 64 [2] 00 62 [2] 1c 65 [2] 00 4a }

  condition:
    any of them
}