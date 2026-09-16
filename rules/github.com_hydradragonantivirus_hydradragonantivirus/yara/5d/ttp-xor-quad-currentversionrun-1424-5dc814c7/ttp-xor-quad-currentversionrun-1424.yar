rule TTP_XOR_QUAD_CurrentVersionRun_1424 {
  strings:
    $key_1424 = { 47 4b [2] 63 45 [2] 48 69 [2] 66 4b [2] 72 50 [2] 7d 4a [2] 63 57 [2] 61 56 [2] 7a 50 [2] 66 57 [2] 7a 78 }

  condition:
    any of them
}