rule TTP_XOR_QUAD_CurrentVersionRun_11e0 {
  strings:
    $key_11e0 = { 42 8f [2] 66 81 [2] 4d ad [2] 63 8f [2] 77 94 [2] 78 8e [2] 66 93 [2] 64 92 [2] 7f 94 [2] 63 93 [2] 7f bc }

  condition:
    any of them
}