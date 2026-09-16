rule TTP_XOR_QUAD_CurrentVersionRun_ec18 {
  strings:
    $key_ec18 = { bf 77 [2] 9b 79 [2] b0 55 [2] 9e 77 [2] 8a 6c [2] 85 76 [2] 9b 6b [2] 99 6a [2] 82 6c [2] 9e 6b [2] 82 44 }

  condition:
    any of them
}