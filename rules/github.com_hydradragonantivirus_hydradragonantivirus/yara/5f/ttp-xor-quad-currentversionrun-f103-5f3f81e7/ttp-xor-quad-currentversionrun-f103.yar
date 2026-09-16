rule TTP_XOR_QUAD_CurrentVersionRun_f103 {
  strings:
    $key_f103 = { a2 6c [2] 86 62 [2] ad 4e [2] 83 6c [2] 97 77 [2] 98 6d [2] 86 70 [2] 84 71 [2] 9f 77 [2] 83 70 [2] 9f 5f }

  condition:
    any of them
}