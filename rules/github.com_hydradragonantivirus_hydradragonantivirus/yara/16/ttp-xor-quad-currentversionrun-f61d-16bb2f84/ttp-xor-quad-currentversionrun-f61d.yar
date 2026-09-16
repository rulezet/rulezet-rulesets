rule TTP_XOR_QUAD_CurrentVersionRun_f61d {
  strings:
    $key_f61d = { a5 72 [2] 81 7c [2] aa 50 [2] 84 72 [2] 90 69 [2] 9f 73 [2] 81 6e [2] 83 6f [2] 98 69 [2] 84 6e [2] 98 41 }

  condition:
    any of them
}