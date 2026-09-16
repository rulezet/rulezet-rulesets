rule TTP_XOR_QUAD_CurrentVersionRun_ddd0 {
  strings:
    $key_ddd0 = { 8e bf [2] aa b1 [2] 81 9d [2] af bf [2] bb a4 [2] b4 be [2] aa a3 [2] a8 a2 [2] b3 a4 [2] af a3 [2] b3 8c }

  condition:
    any of them
}