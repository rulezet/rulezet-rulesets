rule TTP_XOR_QUAD_CurrentVersionRun_6685 {
  strings:
    $key_6685 = { 35 ea [2] 11 e4 [2] 3a c8 [2] 14 ea [2] 00 f1 [2] 0f eb [2] 11 f6 [2] 13 f7 [2] 08 f1 [2] 14 f6 [2] 08 d9 }

  condition:
    any of them
}