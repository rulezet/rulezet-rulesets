rule TTP_XOR_QUAD_CurrentVersionRun_ec32 {
  strings:
    $key_ec32 = { bf 5d [2] 9b 53 [2] b0 7f [2] 9e 5d [2] 8a 46 [2] 85 5c [2] 9b 41 [2] 99 40 [2] 82 46 [2] 9e 41 [2] 82 6e }

  condition:
    any of them
}