rule TTP_XOR_QUAD_CurrentVersionRun_ec1a {
  strings:
    $key_ec1a = { bf 75 [2] 9b 7b [2] b0 57 [2] 9e 75 [2] 8a 6e [2] 85 74 [2] 9b 69 [2] 99 68 [2] 82 6e [2] 9e 69 [2] 82 46 }

  condition:
    any of them
}