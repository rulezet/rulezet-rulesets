rule TTP_XOR_QUAD_CurrentVersionRun_e22e {
  strings:
    $key_e22e = { b1 41 [2] 95 4f [2] be 63 [2] 90 41 [2] 84 5a [2] 8b 40 [2] 95 5d [2] 97 5c [2] 8c 5a [2] 90 5d [2] 8c 72 }

  condition:
    any of them
}