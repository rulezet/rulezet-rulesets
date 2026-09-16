rule TTP_XOR_QUAD_CurrentVersionRun_e4fa {
  strings:
    $key_e4fa = { b7 95 [2] 93 9b [2] b8 b7 [2] 96 95 [2] 82 8e [2] 8d 94 [2] 93 89 [2] 91 88 [2] 8a 8e [2] 96 89 [2] 8a a6 }

  condition:
    any of them
}