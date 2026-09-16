rule TTP_XOR_QUAD_CurrentVersionRun_f31f {
  strings:
    $key_f31f = { a0 70 [2] 84 7e [2] af 52 [2] 81 70 [2] 95 6b [2] 9a 71 [2] 84 6c [2] 86 6d [2] 9d 6b [2] 81 6c [2] 9d 43 }

  condition:
    any of them
}