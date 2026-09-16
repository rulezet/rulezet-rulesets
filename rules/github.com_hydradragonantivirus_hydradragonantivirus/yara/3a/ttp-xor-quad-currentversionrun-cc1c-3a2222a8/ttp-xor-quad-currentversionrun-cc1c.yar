rule TTP_XOR_QUAD_CurrentVersionRun_cc1c {
  strings:
    $key_cc1c = { 9f 73 [2] bb 7d [2] 90 51 [2] be 73 [2] aa 68 [2] a5 72 [2] bb 6f [2] b9 6e [2] a2 68 [2] be 6f [2] a2 40 }

  condition:
    any of them
}