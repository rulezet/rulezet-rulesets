rule TTP_XOR_QUAD_CurrentVersionRun_ec31 {
  strings:
    $key_ec31 = { bf 5e [2] 9b 50 [2] b0 7c [2] 9e 5e [2] 8a 45 [2] 85 5f [2] 9b 42 [2] 99 43 [2] 82 45 [2] 9e 42 [2] 82 6d }

  condition:
    any of them
}