rule TTP_XOR_QUAD_CurrentVersionRun_30fb {
  strings:
    $key_30fb = { 63 94 [2] 47 9a [2] 6c b6 [2] 42 94 [2] 56 8f [2] 59 95 [2] 47 88 [2] 45 89 [2] 5e 8f [2] 42 88 [2] 5e a7 }

  condition:
    any of them
}