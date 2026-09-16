rule TTP_XOR_QUAD_CurrentVersionRun_ec1d {
  strings:
    $key_ec1d = { bf 72 [2] 9b 7c [2] b0 50 [2] 9e 72 [2] 8a 69 [2] 85 73 [2] 9b 6e [2] 99 6f [2] 82 69 [2] 9e 6e [2] 82 41 }

  condition:
    any of them
}