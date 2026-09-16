rule TTP_XOR_QUAD_CurrentVersionRun_cc17 {
  strings:
    $key_cc17 = { 9f 78 [2] bb 76 [2] 90 5a [2] be 78 [2] aa 63 [2] a5 79 [2] bb 64 [2] b9 65 [2] a2 63 [2] be 64 [2] a2 4b }

  condition:
    any of them
}