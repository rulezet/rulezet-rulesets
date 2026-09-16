rule TTP_XOR_QUAD_CurrentVersionRun_d859 {
  strings:
    $key_d859 = { 8b 36 [2] af 38 [2] 84 14 [2] aa 36 [2] be 2d [2] b1 37 [2] af 2a [2] ad 2b [2] b6 2d [2] aa 2a [2] b6 05 }

  condition:
    any of them
}