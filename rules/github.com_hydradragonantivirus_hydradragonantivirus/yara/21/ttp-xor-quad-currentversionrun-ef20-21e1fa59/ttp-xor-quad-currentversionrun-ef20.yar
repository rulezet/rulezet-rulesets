rule TTP_XOR_QUAD_CurrentVersionRun_ef20 {
  strings:
    $key_ef20 = { bc 4f [2] 98 41 [2] b3 6d [2] 9d 4f [2] 89 54 [2] 86 4e [2] 98 53 [2] 9a 52 [2] 81 54 [2] 9d 53 [2] 81 7c }

  condition:
    any of them
}