rule TTP_XOR_QUAD_CurrentVersionRun_e200 {
  strings:
    $key_e200 = { b1 6f [2] 95 61 [2] be 4d [2] 90 6f [2] 84 74 [2] 8b 6e [2] 95 73 [2] 97 72 [2] 8c 74 [2] 90 73 [2] 8c 5c }

  condition:
    any of them
}