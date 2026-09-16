rule TTP_XOR_QUAD_CurrentVersionRun_6ee9 {
  strings:
    $key_6ee9 = { 3d 86 [2] 19 88 [2] 32 a4 [2] 1c 86 [2] 08 9d [2] 07 87 [2] 19 9a [2] 1b 9b [2] 00 9d [2] 1c 9a [2] 00 b5 }

  condition:
    any of them
}