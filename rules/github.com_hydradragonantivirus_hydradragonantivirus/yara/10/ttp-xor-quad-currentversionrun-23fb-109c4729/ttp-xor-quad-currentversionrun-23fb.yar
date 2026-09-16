rule TTP_XOR_QUAD_CurrentVersionRun_23fb {
  strings:
    $key_23fb = { 70 94 [2] 54 9a [2] 7f b6 [2] 51 94 [2] 45 8f [2] 4a 95 [2] 54 88 [2] 56 89 [2] 4d 8f [2] 51 88 [2] 4d a7 }

  condition:
    any of them
}