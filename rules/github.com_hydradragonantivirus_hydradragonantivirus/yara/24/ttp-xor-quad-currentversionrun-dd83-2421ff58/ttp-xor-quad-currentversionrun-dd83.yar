rule TTP_XOR_QUAD_CurrentVersionRun_dd83 {
  strings:
    $key_dd83 = { 8e ec [2] aa e2 [2] 81 ce [2] af ec [2] bb f7 [2] b4 ed [2] aa f0 [2] a8 f1 [2] b3 f7 [2] af f0 [2] b3 df }

  condition:
    any of them
}