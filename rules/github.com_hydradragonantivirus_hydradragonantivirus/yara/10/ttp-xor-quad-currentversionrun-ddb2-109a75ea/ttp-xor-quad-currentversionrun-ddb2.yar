rule TTP_XOR_QUAD_CurrentVersionRun_ddb2 {
  strings:
    $key_ddb2 = { 8e dd [2] aa d3 [2] 81 ff [2] af dd [2] bb c6 [2] b4 dc [2] aa c1 [2] a8 c0 [2] b3 c6 [2] af c1 [2] b3 ee }

  condition:
    any of them
}