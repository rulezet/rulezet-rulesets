rule TTP_XOR_QUAD_CurrentVersionRun_39fb {
  strings:
    $key_39fb = { 6a 94 [2] 4e 9a [2] 65 b6 [2] 4b 94 [2] 5f 8f [2] 50 95 [2] 4e 88 [2] 4c 89 [2] 57 8f [2] 4b 88 [2] 57 a7 }

  condition:
    any of them
}