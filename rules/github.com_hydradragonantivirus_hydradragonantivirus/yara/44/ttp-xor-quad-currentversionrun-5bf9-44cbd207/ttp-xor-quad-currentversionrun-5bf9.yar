rule TTP_XOR_QUAD_CurrentVersionRun_5bf9 {
  strings:
    $key_5bf9 = { 08 96 [2] 2c 98 [2] 07 b4 [2] 29 96 [2] 3d 8d [2] 32 97 [2] 2c 8a [2] 2e 8b [2] 35 8d [2] 29 8a [2] 35 a5 }

  condition:
    any of them
}