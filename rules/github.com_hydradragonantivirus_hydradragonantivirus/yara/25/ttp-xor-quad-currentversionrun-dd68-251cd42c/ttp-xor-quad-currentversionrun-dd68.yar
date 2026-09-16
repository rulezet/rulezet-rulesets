rule TTP_XOR_QUAD_CurrentVersionRun_dd68 {
  strings:
    $key_dd68 = { 8e 07 [2] aa 09 [2] 81 25 [2] af 07 [2] bb 1c [2] b4 06 [2] aa 1b [2] a8 1a [2] b3 1c [2] af 1b [2] b3 34 }

  condition:
    any of them
}