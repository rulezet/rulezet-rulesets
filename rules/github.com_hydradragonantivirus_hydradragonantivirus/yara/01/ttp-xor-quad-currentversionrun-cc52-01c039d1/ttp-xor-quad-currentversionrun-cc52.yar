rule TTP_XOR_QUAD_CurrentVersionRun_cc52 {
  strings:
    $key_cc52 = { 9f 3d [2] bb 33 [2] 90 1f [2] be 3d [2] aa 26 [2] a5 3c [2] bb 21 [2] b9 20 [2] a2 26 [2] be 21 [2] a2 0e }

  condition:
    any of them
}