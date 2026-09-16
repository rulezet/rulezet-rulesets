rule TTP_XOR_QUAD_CurrentVersionRun_ef75 {
  strings:
    $key_ef75 = { bc 1a [2] 98 14 [2] b3 38 [2] 9d 1a [2] 89 01 [2] 86 1b [2] 98 06 [2] 9a 07 [2] 81 01 [2] 9d 06 [2] 81 29 }

  condition:
    any of them
}