rule TTP_XOR_QUAD_CurrentVersionRun_ef15 {
  strings:
    $key_ef15 = { bc 7a [2] 98 74 [2] b3 58 [2] 9d 7a [2] 89 61 [2] 86 7b [2] 98 66 [2] 9a 67 [2] 81 61 [2] 9d 66 [2] 81 49 }

  condition:
    any of them
}