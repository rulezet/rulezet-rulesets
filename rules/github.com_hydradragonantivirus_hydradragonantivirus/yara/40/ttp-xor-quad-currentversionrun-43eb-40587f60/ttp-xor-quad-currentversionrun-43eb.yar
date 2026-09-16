rule TTP_XOR_QUAD_CurrentVersionRun_43eb {
  strings:
    $key_43eb = { 10 84 [2] 34 8a [2] 1f a6 [2] 31 84 [2] 25 9f [2] 2a 85 [2] 34 98 [2] 36 99 [2] 2d 9f [2] 31 98 [2] 2d b7 }

  condition:
    any of them
}