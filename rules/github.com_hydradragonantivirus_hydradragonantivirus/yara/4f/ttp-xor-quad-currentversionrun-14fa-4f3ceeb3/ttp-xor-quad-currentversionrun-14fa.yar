rule TTP_XOR_QUAD_CurrentVersionRun_14fa {
  strings:
    $key_14fa = { 47 95 [2] 63 9b [2] 48 b7 [2] 66 95 [2] 72 8e [2] 7d 94 [2] 63 89 [2] 61 88 [2] 7a 8e [2] 66 89 [2] 7a a6 }

  condition:
    any of them
}