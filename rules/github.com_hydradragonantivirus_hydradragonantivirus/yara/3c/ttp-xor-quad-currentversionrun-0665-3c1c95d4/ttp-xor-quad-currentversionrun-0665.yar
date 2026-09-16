rule TTP_XOR_QUAD_CurrentVersionRun_0665 {
  strings:
    $key_0665 = { 55 0a [2] 71 04 [2] 5a 28 [2] 74 0a [2] 60 11 [2] 6f 0b [2] 71 16 [2] 73 17 [2] 68 11 [2] 74 16 [2] 68 39 }

  condition:
    any of them
}