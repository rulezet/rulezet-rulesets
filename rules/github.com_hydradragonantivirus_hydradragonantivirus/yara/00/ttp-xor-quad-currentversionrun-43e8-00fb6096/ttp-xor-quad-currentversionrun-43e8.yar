rule TTP_XOR_QUAD_CurrentVersionRun_43e8 {
  strings:
    $key_43e8 = { 10 87 [2] 34 89 [2] 1f a5 [2] 31 87 [2] 25 9c [2] 2a 86 [2] 34 9b [2] 36 9a [2] 2d 9c [2] 31 9b [2] 2d b4 }

  condition:
    any of them
}