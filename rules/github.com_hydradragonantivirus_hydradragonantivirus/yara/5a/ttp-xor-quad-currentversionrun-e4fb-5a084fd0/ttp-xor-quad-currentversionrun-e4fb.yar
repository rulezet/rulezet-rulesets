rule TTP_XOR_QUAD_CurrentVersionRun_e4fb {
  strings:
    $key_e4fb = { b7 94 [2] 93 9a [2] b8 b6 [2] 96 94 [2] 82 8f [2] 8d 95 [2] 93 88 [2] 91 89 [2] 8a 8f [2] 96 88 [2] 8a a7 }

  condition:
    any of them
}