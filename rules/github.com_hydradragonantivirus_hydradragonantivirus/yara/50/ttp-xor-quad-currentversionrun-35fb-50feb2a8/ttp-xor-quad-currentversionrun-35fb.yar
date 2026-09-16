rule TTP_XOR_QUAD_CurrentVersionRun_35fb {
  strings:
    $key_35fb = { 66 94 [2] 42 9a [2] 69 b6 [2] 47 94 [2] 53 8f [2] 5c 95 [2] 42 88 [2] 40 89 [2] 5b 8f [2] 47 88 [2] 5b a7 }

  condition:
    any of them
}