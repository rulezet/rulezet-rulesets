rule TTP_XOR_QUAD_CurrentVersionRun_ccfc {
  strings:
    $key_ccfc = { 9f 93 [2] bb 9d [2] 90 b1 [2] be 93 [2] aa 88 [2] a5 92 [2] bb 8f [2] b9 8e [2] a2 88 [2] be 8f [2] a2 a0 }

  condition:
    any of them
}