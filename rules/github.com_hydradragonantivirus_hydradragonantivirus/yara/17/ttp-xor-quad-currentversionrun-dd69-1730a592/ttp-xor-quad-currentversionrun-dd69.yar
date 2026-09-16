rule TTP_XOR_QUAD_CurrentVersionRun_dd69 {
  strings:
    $key_dd69 = { 8e 06 [2] aa 08 [2] 81 24 [2] af 06 [2] bb 1d [2] b4 07 [2] aa 1a [2] a8 1b [2] b3 1d [2] af 1a [2] b3 35 }

  condition:
    any of them
}