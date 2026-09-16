rule TTP_XOR_QUAD_CurrentVersionRun_43e0 {
  strings:
    $key_43e0 = { 10 8f [2] 34 81 [2] 1f ad [2] 31 8f [2] 25 94 [2] 2a 8e [2] 34 93 [2] 36 92 [2] 2d 94 [2] 31 93 [2] 2d bc }

  condition:
    any of them
}