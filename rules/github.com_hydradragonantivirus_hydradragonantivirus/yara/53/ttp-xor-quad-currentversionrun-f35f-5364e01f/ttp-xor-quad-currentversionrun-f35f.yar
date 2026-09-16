rule TTP_XOR_QUAD_CurrentVersionRun_f35f {
  strings:
    $key_f35f = { a0 30 [2] 84 3e [2] af 12 [2] 81 30 [2] 95 2b [2] 9a 31 [2] 84 2c [2] 86 2d [2] 9d 2b [2] 81 2c [2] 9d 03 }

  condition:
    any of them
}