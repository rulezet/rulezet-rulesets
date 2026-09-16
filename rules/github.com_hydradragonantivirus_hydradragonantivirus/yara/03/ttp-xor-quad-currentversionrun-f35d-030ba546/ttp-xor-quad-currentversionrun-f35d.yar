rule TTP_XOR_QUAD_CurrentVersionRun_f35d {
  strings:
    $key_f35d = { a0 32 [2] 84 3c [2] af 10 [2] 81 32 [2] 95 29 [2] 9a 33 [2] 84 2e [2] 86 2f [2] 9d 29 [2] 81 2e [2] 9d 01 }

  condition:
    any of them
}