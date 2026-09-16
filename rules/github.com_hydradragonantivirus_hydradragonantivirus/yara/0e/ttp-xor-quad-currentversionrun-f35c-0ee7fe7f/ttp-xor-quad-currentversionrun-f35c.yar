rule TTP_XOR_QUAD_CurrentVersionRun_f35c {
  strings:
    $key_f35c = { a0 33 [2] 84 3d [2] af 11 [2] 81 33 [2] 95 28 [2] 9a 32 [2] 84 2f [2] 86 2e [2] 9d 28 [2] 81 2f [2] 9d 00 }

  condition:
    any of them
}