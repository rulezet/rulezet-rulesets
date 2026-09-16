rule TTP_XOR_QUAD_CurrentVersionRun_ef7d {
  strings:
    $key_ef7d = { bc 12 [2] 98 1c [2] b3 30 [2] 9d 12 [2] 89 09 [2] 86 13 [2] 98 0e [2] 9a 0f [2] 81 09 [2] 9d 0e [2] 81 21 }

  condition:
    any of them
}