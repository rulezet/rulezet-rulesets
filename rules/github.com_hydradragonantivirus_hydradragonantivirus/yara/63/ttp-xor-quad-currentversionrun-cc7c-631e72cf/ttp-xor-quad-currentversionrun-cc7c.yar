rule TTP_XOR_QUAD_CurrentVersionRun_cc7c {
  strings:
    $key_cc7c = { 9f 13 [2] bb 1d [2] 90 31 [2] be 13 [2] aa 08 [2] a5 12 [2] bb 0f [2] b9 0e [2] a2 08 [2] be 0f [2] a2 20 }

  condition:
    any of them
}