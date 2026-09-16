rule TTP_XOR_QUAD_CurrentVersionRun_e2fb {
  strings:
    $key_e2fb = { b1 94 [2] 95 9a [2] be b6 [2] 90 94 [2] 84 8f [2] 8b 95 [2] 95 88 [2] 97 89 [2] 8c 8f [2] 90 88 [2] 8c a7 }

  condition:
    any of them
}