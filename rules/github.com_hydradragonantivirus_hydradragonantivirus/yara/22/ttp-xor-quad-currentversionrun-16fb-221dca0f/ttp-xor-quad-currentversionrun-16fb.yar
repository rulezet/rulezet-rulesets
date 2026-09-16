rule TTP_XOR_QUAD_CurrentVersionRun_16fb {
  strings:
    $key_16fb = { 45 94 [2] 61 9a [2] 4a b6 [2] 64 94 [2] 70 8f [2] 7f 95 [2] 61 88 [2] 63 89 [2] 78 8f [2] 64 88 [2] 78 a7 }

  condition:
    any of them
}