rule TTP_XOR_QUAD_CurrentVersionRun_d017 {
  strings:
    $key_d017 = { 83 78 [2] a7 76 [2] 8c 5a [2] a2 78 [2] b6 63 [2] b9 79 [2] a7 64 [2] a5 65 [2] be 63 [2] a2 64 [2] be 4b }

  condition:
    any of them
}