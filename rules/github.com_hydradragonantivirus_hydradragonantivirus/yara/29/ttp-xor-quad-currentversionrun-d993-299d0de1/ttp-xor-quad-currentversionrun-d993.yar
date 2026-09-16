rule TTP_XOR_QUAD_CurrentVersionRun_d993 {
  strings:
    $key_d993 = { 8a fc [2] ae f2 [2] 85 de [2] ab fc [2] bf e7 [2] b0 fd [2] ae e0 [2] ac e1 [2] b7 e7 [2] ab e0 [2] b7 cf }

  condition:
    any of them
}