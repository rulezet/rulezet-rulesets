rule TTP_XOR_QUAD_CurrentVersionRun_f30f {
  strings:
    $key_f30f = { a0 60 [2] 84 6e [2] af 42 [2] 81 60 [2] 95 7b [2] 9a 61 [2] 84 7c [2] 86 7d [2] 9d 7b [2] 81 7c [2] 9d 53 }

  condition:
    any of them
}