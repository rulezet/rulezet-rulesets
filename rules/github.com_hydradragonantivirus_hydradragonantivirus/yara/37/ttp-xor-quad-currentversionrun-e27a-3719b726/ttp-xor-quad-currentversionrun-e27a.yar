rule TTP_XOR_QUAD_CurrentVersionRun_e27a {
  strings:
    $key_e27a = { b1 15 [2] 95 1b [2] be 37 [2] 90 15 [2] 84 0e [2] 8b 14 [2] 95 09 [2] 97 08 [2] 8c 0e [2] 90 09 [2] 8c 26 }

  condition:
    any of them
}