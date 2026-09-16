rule TTP_XOR_QUAD_CurrentVersionRun_ec4d {
  strings:
    $key_ec4d = { bf 22 [2] 9b 2c [2] b0 00 [2] 9e 22 [2] 8a 39 [2] 85 23 [2] 9b 3e [2] 99 3f [2] 82 39 [2] 9e 3e [2] 82 11 }

  condition:
    any of them
}