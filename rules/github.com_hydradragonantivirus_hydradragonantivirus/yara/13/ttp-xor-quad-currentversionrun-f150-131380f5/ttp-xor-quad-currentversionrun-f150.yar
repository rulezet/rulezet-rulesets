rule TTP_XOR_QUAD_CurrentVersionRun_f150 {
  strings:
    $key_f150 = { a2 3f [2] 86 31 [2] ad 1d [2] 83 3f [2] 97 24 [2] 98 3e [2] 86 23 [2] 84 22 [2] 9f 24 [2] 83 23 [2] 9f 0c }

  condition:
    any of them
}