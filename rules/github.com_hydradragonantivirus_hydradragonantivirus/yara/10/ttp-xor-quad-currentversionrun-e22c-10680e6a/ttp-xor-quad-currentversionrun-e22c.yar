rule TTP_XOR_QUAD_CurrentVersionRun_e22c {
  strings:
    $key_e22c = { b1 43 [2] 95 4d [2] be 61 [2] 90 43 [2] 84 58 [2] 8b 42 [2] 95 5f [2] 97 5e [2] 8c 58 [2] 90 5f [2] 8c 70 }

  condition:
    any of them
}