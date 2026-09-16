rule TTP_XOR_QUAD_CurrentVersionRun_43e9 {
  strings:
    $key_43e9 = { 10 86 [2] 34 88 [2] 1f a4 [2] 31 86 [2] 25 9d [2] 2a 87 [2] 34 9a [2] 36 9b [2] 2d 9d [2] 31 9a [2] 2d b5 }

  condition:
    any of them
}