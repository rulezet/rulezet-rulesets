rule TTP_XOR_QUAD_CurrentVersionRun_ef40 {
  strings:
    $key_ef40 = { bc 2f [2] 98 21 [2] b3 0d [2] 9d 2f [2] 89 34 [2] 86 2e [2] 98 33 [2] 9a 32 [2] 81 34 [2] 9d 33 [2] 81 1c }

  condition:
    any of them
}