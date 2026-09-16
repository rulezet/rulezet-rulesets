rule TTP_XOR_QUAD_CurrentVersionRun_10fb {
  strings:
    $key_10fb = { 43 94 [2] 67 9a [2] 4c b6 [2] 62 94 [2] 76 8f [2] 79 95 [2] 67 88 [2] 65 89 [2] 7e 8f [2] 62 88 [2] 7e a7 }

  condition:
    any of them
}