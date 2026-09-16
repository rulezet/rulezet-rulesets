rule TTP_XOR_QUAD_CurrentVersionRun_ccfd {
  strings:
    $key_ccfd = { 9f 92 [2] bb 9c [2] 90 b0 [2] be 92 [2] aa 89 [2] a5 93 [2] bb 8e [2] b9 8f [2] a2 89 [2] be 8e [2] a2 a1 }

  condition:
    any of them
}