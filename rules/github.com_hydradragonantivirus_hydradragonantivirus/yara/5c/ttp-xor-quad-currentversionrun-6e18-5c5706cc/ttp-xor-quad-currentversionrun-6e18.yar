rule TTP_XOR_QUAD_CurrentVersionRun_6e18 {
  strings:
    $key_6e18 = { 3d 77 [2] 19 79 [2] 32 55 [2] 1c 77 [2] 08 6c [2] 07 76 [2] 19 6b [2] 1b 6a [2] 00 6c [2] 1c 6b [2] 00 44 }

  condition:
    any of them
}