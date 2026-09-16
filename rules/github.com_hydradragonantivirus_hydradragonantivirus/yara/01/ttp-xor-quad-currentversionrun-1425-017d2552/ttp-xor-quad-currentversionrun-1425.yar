rule TTP_XOR_QUAD_CurrentVersionRun_1425 {
  strings:
    $key_1425 = { 47 4a [2] 63 44 [2] 48 68 [2] 66 4a [2] 72 51 [2] 7d 4b [2] 63 56 [2] 61 57 [2] 7a 51 [2] 66 56 [2] 7a 79 }

  condition:
    any of them
}