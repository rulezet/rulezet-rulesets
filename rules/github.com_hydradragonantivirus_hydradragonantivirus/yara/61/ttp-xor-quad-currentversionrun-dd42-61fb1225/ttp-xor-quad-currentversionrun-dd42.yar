rule TTP_XOR_QUAD_CurrentVersionRun_dd42 {
  strings:
    $key_dd42 = { 8e 2d [2] aa 23 [2] 81 0f [2] af 2d [2] bb 36 [2] b4 2c [2] aa 31 [2] a8 30 [2] b3 36 [2] af 31 [2] b3 1e }

  condition:
    any of them
}