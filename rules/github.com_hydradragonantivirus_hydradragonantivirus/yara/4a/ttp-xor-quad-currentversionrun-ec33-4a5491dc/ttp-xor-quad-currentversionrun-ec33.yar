rule TTP_XOR_QUAD_CurrentVersionRun_ec33 {
  strings:
    $key_ec33 = { bf 5c [2] 9b 52 [2] b0 7e [2] 9e 5c [2] 8a 47 [2] 85 5d [2] 9b 40 [2] 99 41 [2] 82 47 [2] 9e 40 [2] 82 6f }

  condition:
    any of them
}