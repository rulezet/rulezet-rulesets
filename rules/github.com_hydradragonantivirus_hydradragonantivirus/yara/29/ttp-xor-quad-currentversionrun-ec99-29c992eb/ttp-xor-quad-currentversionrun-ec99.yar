rule TTP_XOR_QUAD_CurrentVersionRun_ec99 {
  strings:
    $key_ec99 = { bf f6 [2] 9b f8 [2] b0 d4 [2] 9e f6 [2] 8a ed [2] 85 f7 [2] 9b ea [2] 99 eb [2] 82 ed [2] 9e ea [2] 82 c5 }

  condition:
    any of them
}