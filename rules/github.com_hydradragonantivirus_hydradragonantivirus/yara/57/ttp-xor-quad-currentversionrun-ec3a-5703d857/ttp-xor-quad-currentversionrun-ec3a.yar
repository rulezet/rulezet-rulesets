rule TTP_XOR_QUAD_CurrentVersionRun_ec3a {
  strings:
    $key_ec3a = { bf 55 [2] 9b 5b [2] b0 77 [2] 9e 55 [2] 8a 4e [2] 85 54 [2] 9b 49 [2] 99 48 [2] 82 4e [2] 9e 49 [2] 82 66 }

  condition:
    any of them
}