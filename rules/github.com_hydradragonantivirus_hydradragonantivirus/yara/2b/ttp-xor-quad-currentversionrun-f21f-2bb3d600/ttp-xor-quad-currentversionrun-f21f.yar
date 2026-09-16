rule TTP_XOR_QUAD_CurrentVersionRun_f21f {
  strings:
    $key_f21f = { a1 70 [2] 85 7e [2] ae 52 [2] 80 70 [2] 94 6b [2] 9b 71 [2] 85 6c [2] 87 6d [2] 9c 6b [2] 80 6c [2] 9c 43 }

  condition:
    any of them
}