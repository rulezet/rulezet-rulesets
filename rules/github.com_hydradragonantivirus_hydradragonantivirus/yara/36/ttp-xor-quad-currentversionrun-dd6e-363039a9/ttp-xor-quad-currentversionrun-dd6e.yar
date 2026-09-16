rule TTP_XOR_QUAD_CurrentVersionRun_dd6e {
  strings:
    $key_dd6e = { 8e 01 [2] aa 0f [2] 81 23 [2] af 01 [2] bb 1a [2] b4 00 [2] aa 1d [2] a8 1c [2] b3 1a [2] af 1d [2] b3 32 }

  condition:
    any of them
}