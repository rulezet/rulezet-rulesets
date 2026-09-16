rule TTP_XOR_QUAD_CurrentVersionRun_6e76 {
  strings:
    $key_6e76 = { 3d 19 [2] 19 17 [2] 32 3b [2] 1c 19 [2] 08 02 [2] 07 18 [2] 19 05 [2] 1b 04 [2] 00 02 [2] 1c 05 [2] 00 2a }

  condition:
    any of them
}