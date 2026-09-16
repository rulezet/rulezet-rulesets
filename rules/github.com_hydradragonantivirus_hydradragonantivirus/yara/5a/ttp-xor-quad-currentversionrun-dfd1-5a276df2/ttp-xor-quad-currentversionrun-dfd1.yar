rule TTP_XOR_QUAD_CurrentVersionRun_dfd1 {
  strings:
    $key_dfd1 = { 8c be [2] a8 b0 [2] 83 9c [2] ad be [2] b9 a5 [2] b6 bf [2] a8 a2 [2] aa a3 [2] b1 a5 [2] ad a2 [2] b1 8d }

  condition:
    any of them
}