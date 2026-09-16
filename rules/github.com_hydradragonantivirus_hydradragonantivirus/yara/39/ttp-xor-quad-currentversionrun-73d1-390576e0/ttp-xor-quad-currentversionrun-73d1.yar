rule TTP_XOR_QUAD_CurrentVersionRun_73d1 {
  strings:
    $key_73d1 = { 20 be [2] 04 b0 [2] 2f 9c [2] 01 be [2] 15 a5 [2] 1a bf [2] 04 a2 [2] 06 a3 [2] 1d a5 [2] 01 a2 [2] 1d 8d }

  condition:
    any of them
}