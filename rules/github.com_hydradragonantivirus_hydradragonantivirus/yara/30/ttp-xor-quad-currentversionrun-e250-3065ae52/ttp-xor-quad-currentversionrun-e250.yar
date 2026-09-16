rule TTP_XOR_QUAD_CurrentVersionRun_e250 {
  strings:
    $key_e250 = { b1 3f [2] 95 31 [2] be 1d [2] 90 3f [2] 84 24 [2] 8b 3e [2] 95 23 [2] 97 22 [2] 8c 24 [2] 90 23 [2] 8c 0c }

  condition:
    any of them
}