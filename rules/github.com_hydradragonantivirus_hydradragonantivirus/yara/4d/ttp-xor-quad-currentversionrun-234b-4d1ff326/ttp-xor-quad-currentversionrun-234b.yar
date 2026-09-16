rule TTP_XOR_QUAD_CurrentVersionRun_234b {
  strings:
    $key_234b = { 70 24 [2] 54 2a [2] 7f 06 [2] 51 24 [2] 45 3f [2] 4a 25 [2] 54 38 [2] 56 39 [2] 4d 3f [2] 51 38 [2] 4d 17 }

  condition:
    any of them
}