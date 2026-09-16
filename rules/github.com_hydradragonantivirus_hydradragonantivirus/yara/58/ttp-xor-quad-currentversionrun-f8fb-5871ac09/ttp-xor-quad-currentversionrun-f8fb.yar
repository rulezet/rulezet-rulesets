rule TTP_XOR_QUAD_CurrentVersionRun_f8fb {
  strings:
    $key_f8fb = { ab 94 [2] 8f 9a [2] a4 b6 [2] 8a 94 [2] 9e 8f [2] 91 95 [2] 8f 88 [2] 8d 89 [2] 96 8f [2] 8a 88 [2] 96 a7 }

  condition:
    any of them
}