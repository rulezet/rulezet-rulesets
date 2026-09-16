rule TTP_XOR_QUAD_CurrentVersionRun_ce91 {
  strings:
    $key_ce91 = { 9d fe [2] b9 f0 [2] 92 dc [2] bc fe [2] a8 e5 [2] a7 ff [2] b9 e2 [2] bb e3 [2] a0 e5 [2] bc e2 [2] a0 cd }

  condition:
    any of them
}