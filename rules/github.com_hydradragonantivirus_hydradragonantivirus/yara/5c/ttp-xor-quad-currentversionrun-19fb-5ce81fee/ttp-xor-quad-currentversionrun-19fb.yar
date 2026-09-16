rule TTP_XOR_QUAD_CurrentVersionRun_19fb {
  strings:
    $key_19fb = { 4a 94 [2] 6e 9a [2] 45 b6 [2] 6b 94 [2] 7f 8f [2] 70 95 [2] 6e 88 [2] 6c 89 [2] 77 8f [2] 6b 88 [2] 77 a7 }

  condition:
    any of them
}