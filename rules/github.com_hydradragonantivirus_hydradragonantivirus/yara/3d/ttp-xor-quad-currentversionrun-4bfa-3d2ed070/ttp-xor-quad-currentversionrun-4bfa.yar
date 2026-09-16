rule TTP_XOR_QUAD_CurrentVersionRun_4bfa {
  strings:
    $key_4bfa = { 18 95 [2] 3c 9b [2] 17 b7 [2] 39 95 [2] 2d 8e [2] 22 94 [2] 3c 89 [2] 3e 88 [2] 25 8e [2] 39 89 [2] 25 a6 }

  condition:
    any of them
}