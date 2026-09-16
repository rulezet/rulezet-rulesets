rule TTP_XOR_QUAD_CurrentVersionRun_d8d0 {
  strings:
    $key_d8d0 = { 8b bf [2] af b1 [2] 84 9d [2] aa bf [2] be a4 [2] b1 be [2] af a3 [2] ad a2 [2] b6 a4 [2] aa a3 [2] b6 8c }

  condition:
    any of them
}