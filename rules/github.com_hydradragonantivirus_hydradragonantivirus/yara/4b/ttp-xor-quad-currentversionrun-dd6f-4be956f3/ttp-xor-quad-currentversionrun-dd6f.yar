rule TTP_XOR_QUAD_CurrentVersionRun_dd6f {
  strings:
    $key_dd6f = { 8e 00 [2] aa 0e [2] 81 22 [2] af 00 [2] bb 1b [2] b4 01 [2] aa 1c [2] a8 1d [2] b3 1b [2] af 1c [2] b3 33 }

  condition:
    any of them
}