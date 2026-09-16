rule TTP_XOR_QUAD_CurrentVersionRun_0165 {
  strings:
    $key_0165 = { 52 0a [2] 76 04 [2] 5d 28 [2] 73 0a [2] 67 11 [2] 68 0b [2] 76 16 [2] 74 17 [2] 6f 11 [2] 73 16 [2] 6f 39 }

  condition:
    any of them
}