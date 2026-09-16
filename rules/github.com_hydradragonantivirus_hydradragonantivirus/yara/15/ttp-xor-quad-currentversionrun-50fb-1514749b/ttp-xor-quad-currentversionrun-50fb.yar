rule TTP_XOR_QUAD_CurrentVersionRun_50fb {
  strings:
    $key_50fb = { 03 94 [2] 27 9a [2] 0c b6 [2] 22 94 [2] 36 8f [2] 39 95 [2] 27 88 [2] 25 89 [2] 3e 8f [2] 22 88 [2] 3e a7 }

  condition:
    any of them
}