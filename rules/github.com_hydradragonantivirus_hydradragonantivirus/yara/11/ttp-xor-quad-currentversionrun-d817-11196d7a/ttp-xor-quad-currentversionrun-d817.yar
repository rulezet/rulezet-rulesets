rule TTP_XOR_QUAD_CurrentVersionRun_d817 {
  strings:
    $key_d817 = { 8b 78 [2] af 76 [2] 84 5a [2] aa 78 [2] be 63 [2] b1 79 [2] af 64 [2] ad 65 [2] b6 63 [2] aa 64 [2] b6 4b }

  condition:
    any of them
}