rule TTP_XOR_QUAD_CurrentVersionRun_ef7a {
  strings:
    $key_ef7a = { bc 15 [2] 98 1b [2] b3 37 [2] 9d 15 [2] 89 0e [2] 86 14 [2] 98 09 [2] 9a 08 [2] 81 0e [2] 9d 09 [2] 81 26 }

  condition:
    any of them
}