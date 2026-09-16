rule TTP_XOR_QUAD_CurrentVersionRun_ef5a {
  strings:
    $key_ef5a = { bc 35 [2] 98 3b [2] b3 17 [2] 9d 35 [2] 89 2e [2] 86 34 [2] 98 29 [2] 9a 28 [2] 81 2e [2] 9d 29 [2] 81 06 }

  condition:
    any of them
}