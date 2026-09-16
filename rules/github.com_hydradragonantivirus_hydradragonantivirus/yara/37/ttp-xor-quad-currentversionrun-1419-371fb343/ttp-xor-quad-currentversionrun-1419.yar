rule TTP_XOR_QUAD_CurrentVersionRun_1419 {
  strings:
    $key_1419 = { 47 76 [2] 63 78 [2] 48 54 [2] 66 76 [2] 72 6d [2] 7d 77 [2] 63 6a [2] 61 6b [2] 7a 6d [2] 66 6a [2] 7a 45 }

  condition:
    any of them
}