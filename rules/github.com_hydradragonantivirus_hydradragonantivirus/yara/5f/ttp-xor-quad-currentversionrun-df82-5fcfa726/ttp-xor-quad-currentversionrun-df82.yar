rule TTP_XOR_QUAD_CurrentVersionRun_df82 {
  strings:
    $key_df82 = { 8c ed [2] a8 e3 [2] 83 cf [2] ad ed [2] b9 f6 [2] b6 ec [2] a8 f1 [2] aa f0 [2] b1 f6 [2] ad f1 [2] b1 de }

  condition:
    any of them
}