rule TTP_XOR_QUAD_CurrentVersionRun_3f17 {
  strings:
    $key_3f17 = { 6c 78 [2] 48 76 [2] 63 5a [2] 4d 78 [2] 59 63 [2] 56 79 [2] 48 64 [2] 4a 65 [2] 51 63 [2] 4d 64 [2] 51 4b }

  condition:
    any of them
}