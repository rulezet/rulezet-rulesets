rule TTP_XOR_QUAD_CurrentVersionRun_f62d {
  strings:
    $key_f62d = { a5 42 [2] 81 4c [2] aa 60 [2] 84 42 [2] 90 59 [2] 9f 43 [2] 81 5e [2] 83 5f [2] 98 59 [2] 84 5e [2] 98 71 }

  condition:
    any of them
}