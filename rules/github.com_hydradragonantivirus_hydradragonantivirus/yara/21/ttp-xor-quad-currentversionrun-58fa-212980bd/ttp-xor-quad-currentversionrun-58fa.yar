rule TTP_XOR_QUAD_CurrentVersionRun_58fa {
  strings:
    $key_58fa = { 0b 95 [2] 2f 9b [2] 04 b7 [2] 2a 95 [2] 3e 8e [2] 31 94 [2] 2f 89 [2] 2d 88 [2] 36 8e [2] 2a 89 [2] 36 a6 }

  condition:
    any of them
}