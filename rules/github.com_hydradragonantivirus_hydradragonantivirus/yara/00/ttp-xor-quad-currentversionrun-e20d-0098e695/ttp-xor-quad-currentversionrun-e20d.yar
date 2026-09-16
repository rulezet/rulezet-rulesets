rule TTP_XOR_QUAD_CurrentVersionRun_e20d {
  strings:
    $key_e20d = { b1 62 [2] 95 6c [2] be 40 [2] 90 62 [2] 84 79 [2] 8b 63 [2] 95 7e [2] 97 7f [2] 8c 79 [2] 90 7e [2] 8c 51 }

  condition:
    any of them
}