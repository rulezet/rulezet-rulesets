rule TTP_XOR_QUAD_CurrentVersionRun_71e0 {
  strings:
    $key_71e0 = { 22 8f [2] 06 81 [2] 2d ad [2] 03 8f [2] 17 94 [2] 18 8e [2] 06 93 [2] 04 92 [2] 1f 94 [2] 03 93 [2] 1f bc }

  condition:
    any of them
}