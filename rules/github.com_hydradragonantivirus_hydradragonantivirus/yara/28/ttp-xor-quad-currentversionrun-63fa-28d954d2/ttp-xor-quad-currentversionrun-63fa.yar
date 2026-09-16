rule TTP_XOR_QUAD_CurrentVersionRun_63fa {
  strings:
    $key_63fa = { 30 95 [2] 14 9b [2] 3f b7 [2] 11 95 [2] 05 8e [2] 0a 94 [2] 14 89 [2] 16 88 [2] 0d 8e [2] 11 89 [2] 0d a6 }

  condition:
    any of them
}