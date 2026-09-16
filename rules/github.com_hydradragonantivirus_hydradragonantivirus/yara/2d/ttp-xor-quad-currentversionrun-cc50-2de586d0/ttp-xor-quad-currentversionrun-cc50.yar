rule TTP_XOR_QUAD_CurrentVersionRun_cc50 {
  strings:
    $key_cc50 = { 9f 3f [2] bb 31 [2] 90 1d [2] be 3f [2] aa 24 [2] a5 3e [2] bb 23 [2] b9 22 [2] a2 24 [2] be 23 [2] a2 0c }

  condition:
    any of them
}