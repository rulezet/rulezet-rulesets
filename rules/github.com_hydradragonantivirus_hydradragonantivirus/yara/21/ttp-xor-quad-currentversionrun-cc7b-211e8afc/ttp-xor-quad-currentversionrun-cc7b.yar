rule TTP_XOR_QUAD_CurrentVersionRun_cc7b {
  strings:
    $key_cc7b = { 9f 14 [2] bb 1a [2] 90 36 [2] be 14 [2] aa 0f [2] a5 15 [2] bb 08 [2] b9 09 [2] a2 0f [2] be 08 [2] a2 27 }

  condition:
    any of them
}