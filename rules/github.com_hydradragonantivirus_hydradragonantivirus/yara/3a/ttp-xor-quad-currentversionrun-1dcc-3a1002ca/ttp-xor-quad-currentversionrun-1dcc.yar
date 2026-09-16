rule TTP_XOR_QUAD_CurrentVersionRun_1dcc {
  strings:
    $key_1dcc = { 4e a3 [2] 6a ad [2] 41 81 [2] 6f a3 [2] 7b b8 [2] 74 a2 [2] 6a bf [2] 68 be [2] 73 b8 [2] 6f bf [2] 73 90 }

  condition:
    any of them
}