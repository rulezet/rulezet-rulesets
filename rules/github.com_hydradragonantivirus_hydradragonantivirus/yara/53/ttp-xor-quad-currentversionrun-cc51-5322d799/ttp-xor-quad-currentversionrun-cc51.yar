rule TTP_XOR_QUAD_CurrentVersionRun_cc51 {
  strings:
    $key_cc51 = { 9f 3e [2] bb 30 [2] 90 1c [2] be 3e [2] aa 25 [2] a5 3f [2] bb 22 [2] b9 23 [2] a2 25 [2] be 22 [2] a2 0d }

  condition:
    any of them
}