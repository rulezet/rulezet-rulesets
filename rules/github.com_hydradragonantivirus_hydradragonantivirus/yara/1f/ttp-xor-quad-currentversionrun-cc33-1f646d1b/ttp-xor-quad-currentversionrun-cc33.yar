rule TTP_XOR_QUAD_CurrentVersionRun_cc33 {
  strings:
    $key_cc33 = { 9f 5c [2] bb 52 [2] 90 7e [2] be 5c [2] aa 47 [2] a5 5d [2] bb 40 [2] b9 41 [2] a2 47 [2] be 40 [2] a2 6f }

  condition:
    any of them
}