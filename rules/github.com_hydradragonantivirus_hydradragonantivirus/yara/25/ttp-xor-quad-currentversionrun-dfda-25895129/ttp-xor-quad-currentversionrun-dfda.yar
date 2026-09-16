rule TTP_XOR_QUAD_CurrentVersionRun_dfda {
  strings:
    $key_dfda = { 8c b5 [2] a8 bb [2] 83 97 [2] ad b5 [2] b9 ae [2] b6 b4 [2] a8 a9 [2] aa a8 [2] b1 ae [2] ad a9 [2] b1 86 }

  condition:
    any of them
}