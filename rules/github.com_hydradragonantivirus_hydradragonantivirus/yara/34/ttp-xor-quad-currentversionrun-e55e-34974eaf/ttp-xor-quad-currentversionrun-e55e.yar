rule TTP_XOR_QUAD_CurrentVersionRun_e55e {
  strings:
    $key_e55e = { b6 31 [2] 92 3f [2] b9 13 [2] 97 31 [2] 83 2a [2] 8c 30 [2] 92 2d [2] 90 2c [2] 8b 2a [2] 97 2d [2] 8b 02 }

  condition:
    any of them
}