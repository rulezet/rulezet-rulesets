rule TTP_XOR_QUAD_CurrentVersionRun_0a69 {
  strings:
    $key_0a69 = { 59 06 [2] 7d 08 [2] 56 24 [2] 78 06 [2] 6c 1d [2] 63 07 [2] 7d 1a [2] 7f 1b [2] 64 1d [2] 78 1a [2] 64 35 }

  condition:
    any of them
}