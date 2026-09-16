rule TTP_XOR_QUAD_CurrentVersionRun_e6fb {
  strings:
    $key_e6fb = { b5 94 [2] 91 9a [2] ba b6 [2] 94 94 [2] 80 8f [2] 8f 95 [2] 91 88 [2] 93 89 [2] 88 8f [2] 94 88 [2] 88 a7 }

  condition:
    any of them
}