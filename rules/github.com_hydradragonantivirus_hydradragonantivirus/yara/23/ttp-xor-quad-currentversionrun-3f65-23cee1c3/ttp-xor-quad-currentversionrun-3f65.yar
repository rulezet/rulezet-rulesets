rule TTP_XOR_QUAD_CurrentVersionRun_3f65 {
  strings:
    $key_3f65 = { 6c 0a [2] 48 04 [2] 63 28 [2] 4d 0a [2] 59 11 [2] 56 0b [2] 48 16 [2] 4a 17 [2] 51 11 [2] 4d 16 [2] 51 39 }

  condition:
    any of them
}