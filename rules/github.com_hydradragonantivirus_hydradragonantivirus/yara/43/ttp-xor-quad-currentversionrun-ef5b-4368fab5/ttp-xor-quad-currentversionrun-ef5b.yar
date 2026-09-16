rule TTP_XOR_QUAD_CurrentVersionRun_ef5b {
  strings:
    $key_ef5b = { bc 34 [2] 98 3a [2] b3 16 [2] 9d 34 [2] 89 2f [2] 86 35 [2] 98 28 [2] 9a 29 [2] 81 2f [2] 9d 28 [2] 81 07 }

  condition:
    any of them
}