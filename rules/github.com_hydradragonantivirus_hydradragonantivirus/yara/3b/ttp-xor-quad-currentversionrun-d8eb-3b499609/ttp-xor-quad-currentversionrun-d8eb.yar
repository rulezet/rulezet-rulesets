rule TTP_XOR_QUAD_CurrentVersionRun_d8eb {
  strings:
    $key_d8eb = { 8b 84 [2] af 8a [2] 84 a6 [2] aa 84 [2] be 9f [2] b1 85 [2] af 98 [2] ad 99 [2] b6 9f [2] aa 98 [2] b6 b7 }

  condition:
    any of them
}