rule TTP_XOR_QUAD_CurrentVersionRun_ef6d {
  strings:
    $key_ef6d = { bc 02 [2] 98 0c [2] b3 20 [2] 9d 02 [2] 89 19 [2] 86 03 [2] 98 1e [2] 9a 1f [2] 81 19 [2] 9d 1e [2] 81 31 }

  condition:
    any of them
}