rule TTP_XOR_QUAD_CurrentVersionRun_ef19 {
  strings:
    $key_ef19 = { bc 76 [2] 98 78 [2] b3 54 [2] 9d 76 [2] 89 6d [2] 86 77 [2] 98 6a [2] 9a 6b [2] 81 6d [2] 9d 6a [2] 81 45 }

  condition:
    any of them
}