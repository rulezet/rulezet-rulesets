rule TTP_XOR_QUAD_CurrentVersionRun_0a07 {
  strings:
    $key_0a07 = { 59 68 [2] 7d 66 [2] 56 4a [2] 78 68 [2] 6c 73 [2] 63 69 [2] 7d 74 [2] 7f 75 [2] 64 73 [2] 78 74 [2] 64 5b }

  condition:
    any of them
}