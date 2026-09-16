rule TTP_XOR_QUAD_CurrentVersionRun_f37f {
  strings:
    $key_f37f = { a0 10 [2] 84 1e [2] af 32 [2] 81 10 [2] 95 0b [2] 9a 11 [2] 84 0c [2] 86 0d [2] 9d 0b [2] 81 0c [2] 9d 23 }

  condition:
    any of them
}