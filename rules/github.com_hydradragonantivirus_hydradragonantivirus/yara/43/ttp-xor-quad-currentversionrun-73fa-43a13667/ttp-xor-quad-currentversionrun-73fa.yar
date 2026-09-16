rule TTP_XOR_QUAD_CurrentVersionRun_73fa {
  strings:
    $key_73fa = { 20 95 [2] 04 9b [2] 2f b7 [2] 01 95 [2] 15 8e [2] 1a 94 [2] 04 89 [2] 06 88 [2] 1d 8e [2] 01 89 [2] 1d a6 }

  condition:
    any of them
}