rule TTP_XOR_QUAD_CurrentVersionRun_ec4c {
  strings:
    $key_ec4c = { bf 23 [2] 9b 2d [2] b0 01 [2] 9e 23 [2] 8a 38 [2] 85 22 [2] 9b 3f [2] 99 3e [2] 82 38 [2] 9e 3f [2] 82 10 }

  condition:
    any of them
}