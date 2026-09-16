rule TTP_XOR_QUAD_CurrentVersionRun_ec01 {
  strings:
    $key_ec01 = { bf 6e [2] 9b 60 [2] b0 4c [2] 9e 6e [2] 8a 75 [2] 85 6f [2] 9b 72 [2] 99 73 [2] 82 75 [2] 9e 72 [2] 82 5d }

  condition:
    any of them
}