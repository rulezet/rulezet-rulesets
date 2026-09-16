rule TTP_XOR_QUAD_CurrentVersionRun_cc81 {
  strings:
    $key_cc81 = { 9f ee [2] bb e0 [2] 90 cc [2] be ee [2] aa f5 [2] a5 ef [2] bb f2 [2] b9 f3 [2] a2 f5 [2] be f2 [2] a2 dd }

  condition:
    any of them
}