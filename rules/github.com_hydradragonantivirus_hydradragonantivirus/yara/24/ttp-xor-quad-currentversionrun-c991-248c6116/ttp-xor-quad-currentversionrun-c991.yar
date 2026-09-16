rule TTP_XOR_QUAD_CurrentVersionRun_c991 {
  strings:
    $key_c991 = { 9a fe [2] be f0 [2] 95 dc [2] bb fe [2] af e5 [2] a0 ff [2] be e2 [2] bc e3 [2] a7 e5 [2] bb e2 [2] a7 cd }

  condition:
    any of them
}