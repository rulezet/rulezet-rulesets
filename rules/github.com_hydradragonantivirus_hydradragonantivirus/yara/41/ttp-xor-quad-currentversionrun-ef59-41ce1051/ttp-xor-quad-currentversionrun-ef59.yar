rule TTP_XOR_QUAD_CurrentVersionRun_ef59 {
  strings:
    $key_ef59 = { bc 36 [2] 98 38 [2] b3 14 [2] 9d 36 [2] 89 2d [2] 86 37 [2] 98 2a [2] 9a 2b [2] 81 2d [2] 9d 2a [2] 81 05 }

  condition:
    any of them
}