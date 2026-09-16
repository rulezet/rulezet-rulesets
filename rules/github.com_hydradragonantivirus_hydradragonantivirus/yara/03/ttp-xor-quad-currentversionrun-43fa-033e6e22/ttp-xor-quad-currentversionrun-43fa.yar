rule TTP_XOR_QUAD_CurrentVersionRun_43fa {
  strings:
    $key_43fa = { 10 95 [2] 34 9b [2] 1f b7 [2] 31 95 [2] 25 8e [2] 2a 94 [2] 34 89 [2] 36 88 [2] 2d 8e [2] 31 89 [2] 2d a6 }

  condition:
    any of them
}