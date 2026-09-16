rule TTP_XOR_QUAD_CurrentVersionRun_1624 {
  strings:
    $key_1624 = { 45 4b [2] 61 45 [2] 4a 69 [2] 64 4b [2] 70 50 [2] 7f 4a [2] 61 57 [2] 63 56 [2] 78 50 [2] 64 57 [2] 78 78 }

  condition:
    any of them
}