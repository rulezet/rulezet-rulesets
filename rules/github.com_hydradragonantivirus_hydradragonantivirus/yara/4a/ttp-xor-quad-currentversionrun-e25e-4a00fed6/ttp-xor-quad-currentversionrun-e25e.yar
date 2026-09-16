rule TTP_XOR_QUAD_CurrentVersionRun_e25e {
  strings:
    $key_e25e = { b1 31 [2] 95 3f [2] be 13 [2] 90 31 [2] 84 2a [2] 8b 30 [2] 95 2d [2] 97 2c [2] 8c 2a [2] 90 2d [2] 8c 02 }

  condition:
    any of them
}