rule TTP_XOR_QUAD_CurrentVersionRun_d878 {
  strings:
    $key_d878 = { 8b 17 [2] af 19 [2] 84 35 [2] aa 17 [2] be 0c [2] b1 16 [2] af 0b [2] ad 0a [2] b6 0c [2] aa 0b [2] b6 24 }

  condition:
    any of them
}