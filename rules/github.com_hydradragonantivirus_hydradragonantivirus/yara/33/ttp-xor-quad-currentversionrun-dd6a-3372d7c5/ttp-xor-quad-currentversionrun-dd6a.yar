rule TTP_XOR_QUAD_CurrentVersionRun_dd6a {
  strings:
    $key_dd6a = { 8e 05 [2] aa 0b [2] 81 27 [2] af 05 [2] bb 1e [2] b4 04 [2] aa 19 [2] a8 18 [2] b3 1e [2] af 19 [2] b3 36 }

  condition:
    any of them
}