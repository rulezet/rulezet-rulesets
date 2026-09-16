rule TTP_XOR_QUAD_CurrentVersionRun_6e19 {
  strings:
    $key_6e19 = { 3d 76 [2] 19 78 [2] 32 54 [2] 1c 76 [2] 08 6d [2] 07 77 [2] 19 6a [2] 1b 6b [2] 00 6d [2] 1c 6a [2] 00 45 }

  condition:
    any of them
}