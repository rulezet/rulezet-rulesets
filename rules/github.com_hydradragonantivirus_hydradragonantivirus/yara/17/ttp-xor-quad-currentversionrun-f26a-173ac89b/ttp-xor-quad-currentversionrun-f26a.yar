rule TTP_XOR_QUAD_CurrentVersionRun_f26a {
  strings:
    $key_f26a = { a1 05 [2] 85 0b [2] ae 27 [2] 80 05 [2] 94 1e [2] 9b 04 [2] 85 19 [2] 87 18 [2] 9c 1e [2] 80 19 [2] 9c 36 }

  condition:
    any of them
}