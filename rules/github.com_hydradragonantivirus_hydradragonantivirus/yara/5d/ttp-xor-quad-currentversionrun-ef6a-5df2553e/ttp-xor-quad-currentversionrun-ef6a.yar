rule TTP_XOR_QUAD_CurrentVersionRun_ef6a {
  strings:
    $key_ef6a = { bc 05 [2] 98 0b [2] b3 27 [2] 9d 05 [2] 89 1e [2] 86 04 [2] 98 19 [2] 9a 18 [2] 81 1e [2] 9d 19 [2] 81 36 }

  condition:
    any of them
}