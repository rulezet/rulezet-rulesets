rule TTP_XOR_QUAD_CurrentVersionRun_e273 {
  strings:
    $key_e273 = { b1 1c [2] 95 12 [2] be 3e [2] 90 1c [2] 84 07 [2] 8b 1d [2] 95 00 [2] 97 01 [2] 8c 07 [2] 90 00 [2] 8c 2f }

  condition:
    any of them
}