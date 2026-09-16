rule TTP_XOR_QUAD_CurrentVersionRun_cc4c {
  strings:
    $key_cc4c = { 9f 23 [2] bb 2d [2] 90 01 [2] be 23 [2] aa 38 [2] a5 22 [2] bb 3f [2] b9 3e [2] a2 38 [2] be 3f [2] a2 10 }

  condition:
    any of them
}