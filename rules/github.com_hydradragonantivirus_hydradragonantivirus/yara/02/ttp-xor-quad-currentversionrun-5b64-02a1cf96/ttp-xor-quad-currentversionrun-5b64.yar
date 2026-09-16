rule TTP_XOR_QUAD_CurrentVersionRun_5b64 {
  strings:
    $key_5b64 = { 08 0b [2] 2c 05 [2] 07 29 [2] 29 0b [2] 3d 10 [2] 32 0a [2] 2c 17 [2] 2e 16 [2] 35 10 [2] 29 17 [2] 35 38 }

  condition:
    any of them
}