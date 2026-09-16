rule TTP_XOR_QUAD_CurrentVersionRun_d834 {
  strings:
    $key_d834 = { 8b 5b [2] af 55 [2] 84 79 [2] aa 5b [2] be 40 [2] b1 5a [2] af 47 [2] ad 46 [2] b6 40 [2] aa 47 [2] b6 68 }

  condition:
    any of them
}