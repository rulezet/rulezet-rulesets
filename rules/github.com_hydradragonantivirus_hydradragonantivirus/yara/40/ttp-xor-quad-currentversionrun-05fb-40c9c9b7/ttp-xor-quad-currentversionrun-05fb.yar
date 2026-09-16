rule TTP_XOR_QUAD_CurrentVersionRun_05fb {
  strings:
    $key_05fb = { 56 94 [2] 72 9a [2] 59 b6 [2] 77 94 [2] 63 8f [2] 6c 95 [2] 72 88 [2] 70 89 [2] 6b 8f [2] 77 88 [2] 6b a7 }

  condition:
    any of them
}