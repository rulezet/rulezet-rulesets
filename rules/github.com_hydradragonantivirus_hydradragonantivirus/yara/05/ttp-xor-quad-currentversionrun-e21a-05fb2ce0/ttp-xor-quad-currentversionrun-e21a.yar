rule TTP_XOR_QUAD_CurrentVersionRun_e21a {
  strings:
    $key_e21a = { b1 75 [2] 95 7b [2] be 57 [2] 90 75 [2] 84 6e [2] 8b 74 [2] 95 69 [2] 97 68 [2] 8c 6e [2] 90 69 [2] 8c 46 }

  condition:
    any of them
}