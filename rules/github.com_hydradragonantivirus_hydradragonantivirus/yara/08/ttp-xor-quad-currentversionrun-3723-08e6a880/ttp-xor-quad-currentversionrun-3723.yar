rule TTP_XOR_QUAD_CurrentVersionRun_3723 {
  strings:
    $key_3723 = { 64 4c [2] 40 42 [2] 6b 6e [2] 45 4c [2] 51 57 [2] 5e 4d [2] 40 50 [2] 42 51 [2] 59 57 [2] 45 50 [2] 59 7f }

  condition:
    any of them
}