rule TTP_XOR_QUAD_CurrentVersionRun_f30e {
  strings:
    $key_f30e = { a0 61 [2] 84 6f [2] af 43 [2] 81 61 [2] 95 7a [2] 9a 60 [2] 84 7d [2] 86 7c [2] 9d 7a [2] 81 7d [2] 9d 52 }

  condition:
    any of them
}