rule TTP_XOR_QUAD_CurrentVersionRun_22fb {
  strings:
    $key_22fb = { 71 94 [2] 55 9a [2] 7e b6 [2] 50 94 [2] 44 8f [2] 4b 95 [2] 55 88 [2] 57 89 [2] 4c 8f [2] 50 88 [2] 4c a7 }

  condition:
    any of them
}