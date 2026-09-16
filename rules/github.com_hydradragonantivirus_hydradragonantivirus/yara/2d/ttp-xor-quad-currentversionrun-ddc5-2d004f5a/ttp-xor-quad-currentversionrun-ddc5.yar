rule TTP_XOR_QUAD_CurrentVersionRun_ddc5 {
  strings:
    $key_ddc5 = { 8e aa [2] aa a4 [2] 81 88 [2] af aa [2] bb b1 [2] b4 ab [2] aa b6 [2] a8 b7 [2] b3 b1 [2] af b6 [2] b3 99 }

  condition:
    any of them
}