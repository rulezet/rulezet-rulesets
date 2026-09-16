rule TTP_XOR_QUAD_CurrentVersionRun_dd1b {
  strings:
    $key_dd1b = { 8e 74 [2] aa 7a [2] 81 56 [2] af 74 [2] bb 6f [2] b4 75 [2] aa 68 [2] a8 69 [2] b3 6f [2] af 68 [2] b3 47 }

  condition:
    any of them
}