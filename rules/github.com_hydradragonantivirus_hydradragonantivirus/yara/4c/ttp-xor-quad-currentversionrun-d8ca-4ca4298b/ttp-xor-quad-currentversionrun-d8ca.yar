rule TTP_XOR_QUAD_CurrentVersionRun_d8ca {
  strings:
    $key_d8ca = { 8b a5 [2] af ab [2] 84 87 [2] aa a5 [2] be be [2] b1 a4 [2] af b9 [2] ad b8 [2] b6 be [2] aa b9 [2] b6 96 }

  condition:
    any of them
}