rule TTP_XOR_QUAD_CurrentVersionRun_6dcc {
  strings:
    $key_6dcc = { 3e a3 [2] 1a ad [2] 31 81 [2] 1f a3 [2] 0b b8 [2] 04 a2 [2] 1a bf [2] 18 be [2] 03 b8 [2] 1f bf [2] 03 90 }

  condition:
    any of them
}