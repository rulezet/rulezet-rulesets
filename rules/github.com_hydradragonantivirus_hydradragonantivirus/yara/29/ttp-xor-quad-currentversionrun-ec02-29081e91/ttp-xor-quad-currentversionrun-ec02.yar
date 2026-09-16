rule TTP_XOR_QUAD_CurrentVersionRun_ec02 {
  strings:
    $key_ec02 = { bf 6d [2] 9b 63 [2] b0 4f [2] 9e 6d [2] 8a 76 [2] 85 6c [2] 9b 71 [2] 99 70 [2] 82 76 [2] 9e 71 [2] 82 5e }

  condition:
    any of them
}