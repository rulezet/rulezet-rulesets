rule TTP_XOR_QUAD_CurrentVersionRun_6ee8 {
  strings:
    $key_6ee8 = { 3d 87 [2] 19 89 [2] 32 a5 [2] 1c 87 [2] 08 9c [2] 07 86 [2] 19 9b [2] 1b 9a [2] 00 9c [2] 1c 9b [2] 00 b4 }

  condition:
    any of them
}