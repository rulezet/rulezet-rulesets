rule TTP_XOR_QUAD_CurrentVersionRun_f30c {
  strings:
    $key_f30c = { a0 63 [2] 84 6d [2] af 41 [2] 81 63 [2] 95 78 [2] 9a 62 [2] 84 7f [2] 86 7e [2] 9d 78 [2] 81 7f [2] 9d 50 }

  condition:
    any of them
}