rule TTP_XOR_QUAD_CurrentVersionRun_f600 {
  strings:
    $key_f600 = { a5 6f [2] 81 61 [2] aa 4d [2] 84 6f [2] 90 74 [2] 9f 6e [2] 81 73 [2] 83 72 [2] 98 74 [2] 84 73 [2] 98 5c }

  condition:
    any of them
}