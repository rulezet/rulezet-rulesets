rule TTP_XOR_QUAD_CurrentVersionRun_ddca {
  strings:
    $key_ddca = { 8e a5 [2] aa ab [2] 81 87 [2] af a5 [2] bb be [2] b4 a4 [2] aa b9 [2] a8 b8 [2] b3 be [2] af b9 [2] b3 96 }

  condition:
    any of them
}