rule TTP_XOR_QUAD_CurrentVersionRun_f30a {
  strings:
    $key_f30a = { a0 65 [2] 84 6b [2] af 47 [2] 81 65 [2] 95 7e [2] 9a 64 [2] 84 79 [2] 86 78 [2] 9d 7e [2] 81 79 [2] 9d 56 }

  condition:
    any of them
}