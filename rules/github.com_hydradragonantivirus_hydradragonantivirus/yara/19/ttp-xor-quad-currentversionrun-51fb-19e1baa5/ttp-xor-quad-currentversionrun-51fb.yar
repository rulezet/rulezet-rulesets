rule TTP_XOR_QUAD_CurrentVersionRun_51fb {
  strings:
    $key_51fb = { 02 94 [2] 26 9a [2] 0d b6 [2] 23 94 [2] 37 8f [2] 38 95 [2] 26 88 [2] 24 89 [2] 3f 8f [2] 23 88 [2] 3f a7 }

  condition:
    any of them
}