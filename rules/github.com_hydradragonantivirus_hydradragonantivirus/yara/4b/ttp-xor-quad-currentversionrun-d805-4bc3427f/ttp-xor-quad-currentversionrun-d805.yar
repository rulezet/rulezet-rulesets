rule TTP_XOR_QUAD_CurrentVersionRun_d805 {
  strings:
    $key_d805 = { 8b 6a [2] af 64 [2] 84 48 [2] aa 6a [2] be 71 [2] b1 6b [2] af 76 [2] ad 77 [2] b6 71 [2] aa 76 [2] b6 59 }

  condition:
    any of them
}