rule TTP_XOR_QUAD_CurrentVersionRun_cc91 {
  strings:
    $key_cc91 = { 9f fe [2] bb f0 [2] 90 dc [2] be fe [2] aa e5 [2] a5 ff [2] bb e2 [2] b9 e3 [2] a2 e5 [2] be e2 [2] a2 cd }

  condition:
    any of them
}