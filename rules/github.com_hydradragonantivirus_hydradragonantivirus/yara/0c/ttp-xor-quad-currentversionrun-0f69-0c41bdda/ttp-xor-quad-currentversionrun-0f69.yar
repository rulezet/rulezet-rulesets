rule TTP_XOR_QUAD_CurrentVersionRun_0f69 {
  strings:
    $key_0f69 = { 5c 06 [2] 78 08 [2] 53 24 [2] 7d 06 [2] 69 1d [2] 66 07 [2] 78 1a [2] 7a 1b [2] 61 1d [2] 7d 1a [2] 61 35 }

  condition:
    any of them
}