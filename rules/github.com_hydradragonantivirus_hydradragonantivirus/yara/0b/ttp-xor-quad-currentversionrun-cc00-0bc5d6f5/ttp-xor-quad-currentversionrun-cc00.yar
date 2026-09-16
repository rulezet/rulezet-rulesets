rule TTP_XOR_QUAD_CurrentVersionRun_cc00 {
  strings:
    $key_cc00 = { 9f 6f [2] bb 61 [2] 90 4d [2] be 6f [2] aa 74 [2] a5 6e [2] bb 73 [2] b9 72 [2] a2 74 [2] be 73 [2] a2 5c }

  condition:
    any of them
}