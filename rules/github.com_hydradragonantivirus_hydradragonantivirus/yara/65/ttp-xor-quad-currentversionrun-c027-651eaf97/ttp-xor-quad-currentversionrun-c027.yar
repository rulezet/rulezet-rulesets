rule TTP_XOR_QUAD_CurrentVersionRun_c027 {
  strings:
    $key_c027 = { 93 48 [2] b7 46 [2] 9c 6a [2] b2 48 [2] a6 53 [2] a9 49 [2] b7 54 [2] b5 55 [2] ae 53 [2] b2 54 [2] ae 7b }

  condition:
    any of them
}