rule TTP_XOR_QUAD_CurrentVersionRun_d83b {
  strings:
    $key_d83b = { 8b 54 [2] af 5a [2] 84 76 [2] aa 54 [2] be 4f [2] b1 55 [2] af 48 [2] ad 49 [2] b6 4f [2] aa 48 [2] b6 67 }

  condition:
    any of them
}