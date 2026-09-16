rule TTP_XOR_QUAD_CurrentVersionRun_4509 {
  strings:
    $key_4509 = { 16 66 [2] 32 68 [2] 19 44 [2] 37 66 [2] 23 7d [2] 2c 67 [2] 32 7a [2] 30 7b [2] 2b 7d [2] 37 7a [2] 2b 55 }

  condition:
    any of them
}