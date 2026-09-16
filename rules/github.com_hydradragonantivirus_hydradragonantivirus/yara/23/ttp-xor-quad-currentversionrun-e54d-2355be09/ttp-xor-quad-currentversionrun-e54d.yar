rule TTP_XOR_QUAD_CurrentVersionRun_e54d {
  strings:
    $key_e54d = { b6 22 [2] 92 2c [2] b9 00 [2] 97 22 [2] 83 39 [2] 8c 23 [2] 92 3e [2] 90 3f [2] 8b 39 [2] 97 3e [2] 8b 11 }

  condition:
    any of them
}