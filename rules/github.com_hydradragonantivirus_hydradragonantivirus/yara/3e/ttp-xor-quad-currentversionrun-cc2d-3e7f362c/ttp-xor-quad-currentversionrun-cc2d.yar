rule TTP_XOR_QUAD_CurrentVersionRun_cc2d {
  strings:
    $key_cc2d = { 9f 42 [2] bb 4c [2] 90 60 [2] be 42 [2] aa 59 [2] a5 43 [2] bb 5e [2] b9 5f [2] a2 59 [2] be 5e [2] a2 71 }

  condition:
    any of them
}