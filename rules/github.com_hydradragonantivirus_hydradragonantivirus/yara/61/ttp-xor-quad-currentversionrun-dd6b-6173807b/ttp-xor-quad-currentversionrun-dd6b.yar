rule TTP_XOR_QUAD_CurrentVersionRun_dd6b {
  strings:
    $key_dd6b = { 8e 04 [2] aa 0a [2] 81 26 [2] af 04 [2] bb 1f [2] b4 05 [2] aa 18 [2] a8 19 [2] b3 1f [2] af 18 [2] b3 37 }

  condition:
    any of them
}