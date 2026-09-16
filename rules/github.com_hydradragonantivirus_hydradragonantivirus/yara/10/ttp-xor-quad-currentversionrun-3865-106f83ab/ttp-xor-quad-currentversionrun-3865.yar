rule TTP_XOR_QUAD_CurrentVersionRun_3865 {
  strings:
    $key_3865 = { 6b 0a [2] 4f 04 [2] 64 28 [2] 4a 0a [2] 5e 11 [2] 51 0b [2] 4f 16 [2] 4d 17 [2] 56 11 [2] 4a 16 [2] 56 39 }

  condition:
    any of them
}