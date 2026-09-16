rule TTP_XOR_QUAD_CurrentVersionRun_d848 {
  strings:
    $key_d848 = { 8b 27 [2] af 29 [2] 84 05 [2] aa 27 [2] be 3c [2] b1 26 [2] af 3b [2] ad 3a [2] b6 3c [2] aa 3b [2] b6 14 }

  condition:
    any of them
}