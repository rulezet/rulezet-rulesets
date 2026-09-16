rule TTP_XOR_QUAD_CurrentVersionRun_6ee5 {
  strings:
    $key_6ee5 = { 3d 8a [2] 19 84 [2] 32 a8 [2] 1c 8a [2] 08 91 [2] 07 8b [2] 19 96 [2] 1b 97 [2] 00 91 [2] 1c 96 [2] 00 b9 }

  condition:
    any of them
}