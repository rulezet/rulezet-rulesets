rule TTP_XOR_QUAD_CurrentVersionRun_ef60 {
  strings:
    $key_ef60 = { bc 0f [2] 98 01 [2] b3 2d [2] 9d 0f [2] 89 14 [2] 86 0e [2] 98 13 [2] 9a 12 [2] 81 14 [2] 9d 13 [2] 81 3c }

  condition:
    any of them
}