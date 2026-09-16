rule TTP_XOR_QUAD_CurrentVersionRun_e27c {
  strings:
    $key_e27c = { b1 13 [2] 95 1d [2] be 31 [2] 90 13 [2] 84 08 [2] 8b 12 [2] 95 0f [2] 97 0e [2] 8c 08 [2] 90 0f [2] 8c 20 }

  condition:
    any of them
}