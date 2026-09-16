rule TTP_XOR_QUAD_CurrentVersionRun_6e34 {
  strings:
    $key_6e34 = { 3d 5b [2] 19 55 [2] 32 79 [2] 1c 5b [2] 08 40 [2] 07 5a [2] 19 47 [2] 1b 46 [2] 00 40 [2] 1c 47 [2] 00 68 }

  condition:
    any of them
}