rule TTP_XOR_QUAD_CurrentVersionRun_e500 {
  strings:
    $key_e500 = { b6 6f [2] 92 61 [2] b9 4d [2] 97 6f [2] 83 74 [2] 8c 6e [2] 92 73 [2] 90 72 [2] 8b 74 [2] 97 73 [2] 8b 5c }

  condition:
    any of them
}