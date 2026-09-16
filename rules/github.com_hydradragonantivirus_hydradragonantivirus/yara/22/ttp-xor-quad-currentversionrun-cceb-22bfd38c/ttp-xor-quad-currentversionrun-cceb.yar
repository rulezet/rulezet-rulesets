rule TTP_XOR_QUAD_CurrentVersionRun_cceb {
  strings:
    $key_cceb = { 9f 84 [2] bb 8a [2] 90 a6 [2] be 84 [2] aa 9f [2] a5 85 [2] bb 98 [2] b9 99 [2] a2 9f [2] be 98 [2] a2 b7 }

  condition:
    any of them
}