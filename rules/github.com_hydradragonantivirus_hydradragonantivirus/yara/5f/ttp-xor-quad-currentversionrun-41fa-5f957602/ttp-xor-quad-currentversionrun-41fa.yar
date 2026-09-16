rule TTP_XOR_QUAD_CurrentVersionRun_41fa {
  strings:
    $key_41fa = { 12 95 [2] 36 9b [2] 1d b7 [2] 33 95 [2] 27 8e [2] 28 94 [2] 36 89 [2] 34 88 [2] 2f 8e [2] 33 89 [2] 2f a6 }

  condition:
    any of them
}