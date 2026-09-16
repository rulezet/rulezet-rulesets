rule TTP_XOR_QUAD_CurrentVersionRun_e27f {
  strings:
    $key_e27f = { b1 10 [2] 95 1e [2] be 32 [2] 90 10 [2] 84 0b [2] 8b 11 [2] 95 0c [2] 97 0d [2] 8c 0b [2] 90 0c [2] 8c 23 }

  condition:
    any of them
}