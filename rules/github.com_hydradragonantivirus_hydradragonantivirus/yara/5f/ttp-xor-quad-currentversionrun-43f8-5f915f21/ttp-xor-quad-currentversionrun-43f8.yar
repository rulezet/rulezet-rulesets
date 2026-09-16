rule TTP_XOR_QUAD_CurrentVersionRun_43f8 {
  strings:
    $key_43f8 = { 10 97 [2] 34 99 [2] 1f b5 [2] 31 97 [2] 25 8c [2] 2a 96 [2] 34 8b [2] 36 8a [2] 2d 8c [2] 31 8b [2] 2d a4 }

  condition:
    any of them
}