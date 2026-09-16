rule TTP_XOR_QUAD_CurrentVersionRun_e24d {
  strings:
    $key_e24d = { b1 22 [2] 95 2c [2] be 00 [2] 90 22 [2] 84 39 [2] 8b 23 [2] 95 3e [2] 97 3f [2] 8c 39 [2] 90 3e [2] 8c 11 }

  condition:
    any of them
}