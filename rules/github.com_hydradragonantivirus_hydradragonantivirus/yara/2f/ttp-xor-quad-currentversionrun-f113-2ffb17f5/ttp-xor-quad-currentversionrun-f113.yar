rule TTP_XOR_QUAD_CurrentVersionRun_f113 {
  strings:
    $key_f113 = { a2 7c [2] 86 72 [2] ad 5e [2] 83 7c [2] 97 67 [2] 98 7d [2] 86 60 [2] 84 61 [2] 9f 67 [2] 83 60 [2] 9f 4f }

  condition:
    any of them
}