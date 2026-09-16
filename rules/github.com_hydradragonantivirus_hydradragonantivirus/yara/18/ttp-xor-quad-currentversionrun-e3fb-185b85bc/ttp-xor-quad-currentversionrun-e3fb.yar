rule TTP_XOR_QUAD_CurrentVersionRun_e3fb {
  strings:
    $key_e3fb = { b0 94 [2] 94 9a [2] bf b6 [2] 91 94 [2] 85 8f [2] 8a 95 [2] 94 88 [2] 96 89 [2] 8d 8f [2] 91 88 [2] 8d a7 }

  condition:
    any of them
}