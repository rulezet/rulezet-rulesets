rule TTP_XOR_QUAD_CurrentVersionRun_43a8 {
  strings:
    $key_43a8 = { 10 c7 [2] 34 c9 [2] 1f e5 [2] 31 c7 [2] 25 dc [2] 2a c6 [2] 34 db [2] 36 da [2] 2d dc [2] 31 db [2] 2d f4 }

  condition:
    any of them
}