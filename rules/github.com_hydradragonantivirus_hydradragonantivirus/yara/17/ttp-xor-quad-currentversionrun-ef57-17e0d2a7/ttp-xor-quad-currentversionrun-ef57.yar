rule TTP_XOR_QUAD_CurrentVersionRun_ef57 {
  strings:
    $key_ef57 = { bc 38 [2] 98 36 [2] b3 1a [2] 9d 38 [2] 89 23 [2] 86 39 [2] 98 24 [2] 9a 25 [2] 81 23 [2] 9d 24 [2] 81 0b }

  condition:
    any of them
}