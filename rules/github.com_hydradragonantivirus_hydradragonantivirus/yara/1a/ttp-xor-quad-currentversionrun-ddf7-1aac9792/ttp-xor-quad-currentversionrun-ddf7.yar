rule TTP_XOR_QUAD_CurrentVersionRun_ddf7 {
  strings:
    $key_ddf7 = { 8e 98 [2] aa 96 [2] 81 ba [2] af 98 [2] bb 83 [2] b4 99 [2] aa 84 [2] a8 85 [2] b3 83 [2] af 84 [2] b3 ab }

  condition:
    any of them
}