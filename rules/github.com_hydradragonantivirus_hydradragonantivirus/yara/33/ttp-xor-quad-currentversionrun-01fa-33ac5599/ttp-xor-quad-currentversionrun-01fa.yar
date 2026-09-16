rule TTP_XOR_QUAD_CurrentVersionRun_01fa {
  strings:
    $key_01fa = { 52 95 [2] 76 9b [2] 5d b7 [2] 73 95 [2] 67 8e [2] 68 94 [2] 76 89 [2] 74 88 [2] 6f 8e [2] 73 89 [2] 6f a6 }

  condition:
    any of them
}