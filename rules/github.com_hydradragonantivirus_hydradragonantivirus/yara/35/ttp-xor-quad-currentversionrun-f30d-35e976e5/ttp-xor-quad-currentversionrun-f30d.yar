rule TTP_XOR_QUAD_CurrentVersionRun_f30d {
  strings:
    $key_f30d = { a0 62 [2] 84 6c [2] af 40 [2] 81 62 [2] 95 79 [2] 9a 63 [2] 84 7e [2] 86 7f [2] 9d 79 [2] 81 7e [2] 9d 51 }

  condition:
    any of them
}