rule TTP_XOR_QUAD_CurrentVersionRun_70fb {
  strings:
    $key_70fb = { 23 94 [2] 07 9a [2] 2c b6 [2] 02 94 [2] 16 8f [2] 19 95 [2] 07 88 [2] 05 89 [2] 1e 8f [2] 02 88 [2] 1e a7 }

  condition:
    any of them
}