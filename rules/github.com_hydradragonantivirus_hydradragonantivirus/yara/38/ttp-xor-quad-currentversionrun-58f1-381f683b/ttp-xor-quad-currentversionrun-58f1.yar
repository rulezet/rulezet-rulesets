rule TTP_XOR_QUAD_CurrentVersionRun_58f1 {
  strings:
    $key_58f1 = { 0b 9e [2] 2f 90 [2] 04 bc [2] 2a 9e [2] 3e 85 [2] 31 9f [2] 2f 82 [2] 2d 83 [2] 36 85 [2] 2a 82 [2] 36 ad }

  condition:
    any of them
}