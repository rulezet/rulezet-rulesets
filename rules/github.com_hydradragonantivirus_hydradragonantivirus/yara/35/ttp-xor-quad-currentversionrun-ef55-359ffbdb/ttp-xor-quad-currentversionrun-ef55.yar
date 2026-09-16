rule TTP_XOR_QUAD_CurrentVersionRun_ef55 {
  strings:
    $key_ef55 = { bc 3a [2] 98 34 [2] b3 18 [2] 9d 3a [2] 89 21 [2] 86 3b [2] 98 26 [2] 9a 27 [2] 81 21 [2] 9d 26 [2] 81 09 }

  condition:
    any of them
}