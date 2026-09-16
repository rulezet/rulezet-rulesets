rule TTP_XOR_QUAD_CurrentVersionRun_20fb {
  strings:
    $key_20fb = { 73 94 [2] 57 9a [2] 7c b6 [2] 52 94 [2] 46 8f [2] 49 95 [2] 57 88 [2] 55 89 [2] 4e 8f [2] 52 88 [2] 4e a7 }

  condition:
    any of them
}