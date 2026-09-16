rule TTP_XOR_QUAD_CurrentVersionRun_ccfb {
  strings:
    $key_ccfb = { 9f 94 [2] bb 9a [2] 90 b6 [2] be 94 [2] aa 8f [2] a5 95 [2] bb 88 [2] b9 89 [2] a2 8f [2] be 88 [2] a2 a7 }

  condition:
    any of them
}