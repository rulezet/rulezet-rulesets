rule TTP_XOR_QUAD_CurrentVersionRun_ccf6 {
  strings:
    $key_ccf6 = { 9f 99 [2] bb 97 [2] 90 bb [2] be 99 [2] aa 82 [2] a5 98 [2] bb 85 [2] b9 84 [2] a2 82 [2] be 85 [2] a2 aa }

  condition:
    any of them
}