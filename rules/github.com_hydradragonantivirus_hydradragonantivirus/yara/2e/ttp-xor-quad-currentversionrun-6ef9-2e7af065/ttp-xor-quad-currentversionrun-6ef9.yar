rule TTP_XOR_QUAD_CurrentVersionRun_6ef9 {
  strings:
    $key_6ef9 = { 3d 96 [2] 19 98 [2] 32 b4 [2] 1c 96 [2] 08 8d [2] 07 97 [2] 19 8a [2] 1b 8b [2] 00 8d [2] 1c 8a [2] 00 a5 }

  condition:
    any of them
}