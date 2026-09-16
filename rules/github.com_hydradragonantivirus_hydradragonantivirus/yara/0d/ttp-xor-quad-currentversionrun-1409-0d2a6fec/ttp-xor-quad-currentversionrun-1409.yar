rule TTP_XOR_QUAD_CurrentVersionRun_1409 {
  strings:
    $key_1409 = { 47 66 [2] 63 68 [2] 48 44 [2] 66 66 [2] 72 7d [2] 7d 67 [2] 63 7a [2] 61 7b [2] 7a 7d [2] 66 7a [2] 7a 55 }

  condition:
    any of them
}