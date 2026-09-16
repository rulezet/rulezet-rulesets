rule TTP_XOR_QUAD_CurrentVersionRun_d838 {
  strings:
    $key_d838 = { 8b 57 [2] af 59 [2] 84 75 [2] aa 57 [2] be 4c [2] b1 56 [2] af 4b [2] ad 4a [2] b6 4c [2] aa 4b [2] b6 64 }

  condition:
    any of them
}