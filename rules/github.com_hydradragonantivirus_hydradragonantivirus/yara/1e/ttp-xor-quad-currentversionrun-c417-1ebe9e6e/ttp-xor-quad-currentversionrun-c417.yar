rule TTP_XOR_QUAD_CurrentVersionRun_c417 {
  strings:
    $key_c417 = { 97 78 [2] b3 76 [2] 98 5a [2] b6 78 [2] a2 63 [2] ad 79 [2] b3 64 [2] b1 65 [2] aa 63 [2] b6 64 [2] aa 4b }

  condition:
    any of them
}