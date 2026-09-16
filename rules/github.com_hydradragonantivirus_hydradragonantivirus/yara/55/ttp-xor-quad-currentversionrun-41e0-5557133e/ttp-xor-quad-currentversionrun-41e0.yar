rule TTP_XOR_QUAD_CurrentVersionRun_41e0 {
  strings:
    $key_41e0 = { 12 8f [2] 36 81 [2] 1d ad [2] 33 8f [2] 27 94 [2] 28 8e [2] 36 93 [2] 34 92 [2] 2f 94 [2] 33 93 [2] 2f bc }

  condition:
    any of them
}