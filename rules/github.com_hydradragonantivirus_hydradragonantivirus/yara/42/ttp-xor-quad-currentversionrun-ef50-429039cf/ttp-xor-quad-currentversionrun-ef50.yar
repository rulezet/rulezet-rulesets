rule TTP_XOR_QUAD_CurrentVersionRun_ef50 {
  strings:
    $key_ef50 = { bc 3f [2] 98 31 [2] b3 1d [2] 9d 3f [2] 89 24 [2] 86 3e [2] 98 23 [2] 9a 22 [2] 81 24 [2] 9d 23 [2] 81 0c }

  condition:
    any of them
}