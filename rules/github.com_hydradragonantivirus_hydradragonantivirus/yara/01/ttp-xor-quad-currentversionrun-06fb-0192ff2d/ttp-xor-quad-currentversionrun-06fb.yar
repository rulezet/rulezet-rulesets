rule TTP_XOR_QUAD_CurrentVersionRun_06fb {
  strings:
    $key_06fb = { 55 94 [2] 71 9a [2] 5a b6 [2] 74 94 [2] 60 8f [2] 6f 95 [2] 71 88 [2] 73 89 [2] 68 8f [2] 74 88 [2] 68 a7 }

  condition:
    any of them
}