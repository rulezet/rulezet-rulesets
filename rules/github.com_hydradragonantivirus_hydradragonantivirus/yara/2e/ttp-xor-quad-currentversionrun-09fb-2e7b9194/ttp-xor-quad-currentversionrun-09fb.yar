rule TTP_XOR_QUAD_CurrentVersionRun_09fb {
  strings:
    $key_09fb = { 5a 94 [2] 7e 9a [2] 55 b6 [2] 7b 94 [2] 6f 8f [2] 60 95 [2] 7e 88 [2] 7c 89 [2] 67 8f [2] 7b 88 [2] 67 a7 }

  condition:
    any of them
}