rule TTP_XOR_QUAD_CurrentVersionRun_7180 {
  strings:
    $key_7180 = { 22 ef [2] 06 e1 [2] 2d cd [2] 03 ef [2] 17 f4 [2] 18 ee [2] 06 f3 [2] 04 f2 [2] 1f f4 [2] 03 f3 [2] 1f dc }

  condition:
    any of them
}