rule TTP_XOR_QUAD_CurrentVersionRun_1619 {
  strings:
    $key_1619 = { 45 76 [2] 61 78 [2] 4a 54 [2] 64 76 [2] 70 6d [2] 7f 77 [2] 61 6a [2] 63 6b [2] 78 6d [2] 64 6a [2] 78 45 }

  condition:
    any of them
}