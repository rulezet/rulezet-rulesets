rule TTP_XOR_QUAD_CurrentVersionRun_ccf7 {
  strings:
    $key_ccf7 = { 9f 98 [2] bb 96 [2] 90 ba [2] be 98 [2] aa 83 [2] a5 99 [2] bb 84 [2] b9 85 [2] a2 83 [2] be 84 [2] a2 ab }

  condition:
    any of them
}