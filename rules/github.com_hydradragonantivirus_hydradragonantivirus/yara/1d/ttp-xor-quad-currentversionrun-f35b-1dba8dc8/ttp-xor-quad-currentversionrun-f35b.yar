rule TTP_XOR_QUAD_CurrentVersionRun_f35b {
  strings:
    $key_f35b = { a0 34 [2] 84 3a [2] af 16 [2] 81 34 [2] 95 2f [2] 9a 35 [2] 84 28 [2] 86 29 [2] 9d 2f [2] 81 28 [2] 9d 07 }

  condition:
    any of them
}