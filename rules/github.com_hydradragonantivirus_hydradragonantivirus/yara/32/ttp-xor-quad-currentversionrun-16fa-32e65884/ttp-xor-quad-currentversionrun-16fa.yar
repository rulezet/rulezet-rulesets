rule TTP_XOR_QUAD_CurrentVersionRun_16fa {
  strings:
    $key_16fa = { 45 95 [2] 61 9b [2] 4a b7 [2] 64 95 [2] 70 8e [2] 7f 94 [2] 61 89 [2] 63 88 [2] 78 8e [2] 64 89 [2] 78 a6 }

  condition:
    any of them
}