rule TTP_XOR_QUAD_CurrentVersionRun_d828 {
  strings:
    $key_d828 = { 8b 47 [2] af 49 [2] 84 65 [2] aa 47 [2] be 5c [2] b1 46 [2] af 5b [2] ad 5a [2] b6 5c [2] aa 5b [2] b6 74 }

  condition:
    any of them
}