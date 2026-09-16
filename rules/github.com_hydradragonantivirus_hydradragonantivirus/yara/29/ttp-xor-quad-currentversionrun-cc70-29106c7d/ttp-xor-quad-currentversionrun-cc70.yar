rule TTP_XOR_QUAD_CurrentVersionRun_cc70 {
  strings:
    $key_cc70 = { 9f 1f [2] bb 11 [2] 90 3d [2] be 1f [2] aa 04 [2] a5 1e [2] bb 03 [2] b9 02 [2] a2 04 [2] be 03 [2] a2 2c }

  condition:
    any of them
}