rule TTP_XOR_QUAD_CurrentVersionRun_ccec {
  strings:
    $key_ccec = { 9f 83 [2] bb 8d [2] 90 a1 [2] be 83 [2] aa 98 [2] a5 82 [2] bb 9f [2] b9 9e [2] a2 98 [2] be 9f [2] a2 b0 }

  condition:
    any of them
}