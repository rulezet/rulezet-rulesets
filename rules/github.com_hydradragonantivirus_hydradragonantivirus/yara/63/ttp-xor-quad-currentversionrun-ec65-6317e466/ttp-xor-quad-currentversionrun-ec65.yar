rule TTP_XOR_QUAD_CurrentVersionRun_ec65 {
  strings:
    $key_ec65 = { bf 0a [2] 9b 04 [2] b0 28 [2] 9e 0a [2] 8a 11 [2] 85 0b [2] 9b 16 [2] 99 17 [2] 82 11 [2] 9e 16 [2] 82 39 }

  condition:
    any of them
}