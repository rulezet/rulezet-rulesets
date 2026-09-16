rule TTP_XOR_QUAD_CurrentVersionRun_d84b {
  strings:
    $key_d84b = { 8b 24 [2] af 2a [2] 84 06 [2] aa 24 [2] be 3f [2] b1 25 [2] af 38 [2] ad 39 [2] b6 3f [2] aa 38 [2] b6 17 }

  condition:
    any of them
}