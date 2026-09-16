rule TTP_XOR_QUAD_CurrentVersionRun_ef68 {
  strings:
    $key_ef68 = { bc 07 [2] 98 09 [2] b3 25 [2] 9d 07 [2] 89 1c [2] 86 06 [2] 98 1b [2] 9a 1a [2] 81 1c [2] 9d 1b [2] 81 34 }

  condition:
    any of them
}