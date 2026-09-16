rule TTP_XOR_QUAD_CurrentVersionRun_f11d {
  strings:
    $key_f11d = { a2 72 [2] 86 7c [2] ad 50 [2] 83 72 [2] 97 69 [2] 98 73 [2] 86 6e [2] 84 6f [2] 9f 69 [2] 83 6e [2] 9f 41 }

  condition:
    any of them
}