rule TTP_XOR_QUAD_CurrentVersionRun_f101 {
  strings:
    $key_f101 = { a2 6e [2] 86 60 [2] ad 4c [2] 83 6e [2] 97 75 [2] 98 6f [2] 86 72 [2] 84 73 [2] 9f 75 [2] 83 72 [2] 9f 5d }

  condition:
    any of them
}