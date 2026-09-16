rule TTP_XOR_QUAD_CurrentVersionRun_ef21 {
  strings:
    $key_ef21 = { bc 4e [2] 98 40 [2] b3 6c [2] 9d 4e [2] 89 55 [2] 86 4f [2] 98 52 [2] 9a 53 [2] 81 55 [2] 9d 52 [2] 81 7d }

  condition:
    any of them
}