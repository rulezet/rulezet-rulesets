rule TTP_XOR_QUAD_CurrentVersionRun_ef74 {
  strings:
    $key_ef74 = { bc 1b [2] 98 15 [2] b3 39 [2] 9d 1b [2] 89 00 [2] 86 1a [2] 98 07 [2] 9a 06 [2] 81 00 [2] 9d 07 [2] 81 28 }

  condition:
    any of them
}