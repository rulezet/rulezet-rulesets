rule TTP_XOR_QUAD_CurrentVersionRun_dd82 {
  strings:
    $key_dd82 = { 8e ed [2] aa e3 [2] 81 cf [2] af ed [2] bb f6 [2] b4 ec [2] aa f1 [2] a8 f0 [2] b3 f6 [2] af f1 [2] b3 de }

  condition:
    any of them
}