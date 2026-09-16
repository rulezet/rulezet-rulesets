rule TTP_XOR_QUAD_CurrentVersionRun_f20a {
  strings:
    $key_f20a = { a1 65 [2] 85 6b [2] ae 47 [2] 80 65 [2] 94 7e [2] 9b 64 [2] 85 79 [2] 87 78 [2] 9c 7e [2] 80 79 [2] 9c 56 }

  condition:
    any of them
}