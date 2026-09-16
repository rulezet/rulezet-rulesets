rule TTP_XOR_QUAD_CurrentVersionRun_ec3e {
  strings:
    $key_ec3e = { bf 51 [2] 9b 5f [2] b0 73 [2] 9e 51 [2] 8a 4a [2] 85 50 [2] 9b 4d [2] 99 4c [2] 82 4a [2] 9e 4d [2] 82 62 }

  condition:
    any of them
}