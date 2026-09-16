rule TTP_XOR_QUAD_CurrentVersionRun_ef44 {
  strings:
    $key_ef44 = { bc 2b [2] 98 25 [2] b3 09 [2] 9d 2b [2] 89 30 [2] 86 2a [2] 98 37 [2] 9a 36 [2] 81 30 [2] 9d 37 [2] 81 18 }

  condition:
    any of them
}