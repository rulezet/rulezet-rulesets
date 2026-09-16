rule TTP_XOR_QUAD_CurrentVersionRun_0dcc {
  strings:
    $key_0dcc = { 5e a3 [2] 7a ad [2] 51 81 [2] 7f a3 [2] 6b b8 [2] 64 a2 [2] 7a bf [2] 78 be [2] 63 b8 [2] 7f bf [2] 63 90 }

  condition:
    any of them
}