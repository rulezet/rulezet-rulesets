rule TTP_XOR_QUAD_CurrentVersionRun_cc80 {
  strings:
    $key_cc80 = { 9f ef [2] bb e1 [2] 90 cd [2] be ef [2] aa f4 [2] a5 ee [2] bb f3 [2] b9 f2 [2] a2 f4 [2] be f3 [2] a2 dc }

  condition:
    any of them
}