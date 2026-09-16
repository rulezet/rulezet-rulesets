rule TTP_XOR_QUAD_CurrentVersionRun_ec0f {
  strings:
    $key_ec0f = { bf 60 [2] 9b 6e [2] b0 42 [2] 9e 60 [2] 8a 7b [2] 85 61 [2] 9b 7c [2] 99 7d [2] 82 7b [2] 9e 7c [2] 82 53 }

  condition:
    any of them
}