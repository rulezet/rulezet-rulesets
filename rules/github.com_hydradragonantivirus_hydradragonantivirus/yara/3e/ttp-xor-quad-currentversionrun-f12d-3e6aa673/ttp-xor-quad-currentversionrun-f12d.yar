rule TTP_XOR_QUAD_CurrentVersionRun_f12d {
  strings:
    $key_f12d = { a2 42 [2] 86 4c [2] ad 60 [2] 83 42 [2] 97 59 [2] 98 43 [2] 86 5e [2] 84 5f [2] 9f 59 [2] 83 5e [2] 9f 71 }

  condition:
    any of them
}