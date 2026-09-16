rule TTP_XOR_QUAD_CurrentVersionRun_51fa {
  strings:
    $key_51fa = { 02 95 [2] 26 9b [2] 0d b7 [2] 23 95 [2] 37 8e [2] 38 94 [2] 26 89 [2] 24 88 [2] 3f 8e [2] 23 89 [2] 3f a6 }

  condition:
    any of them
}