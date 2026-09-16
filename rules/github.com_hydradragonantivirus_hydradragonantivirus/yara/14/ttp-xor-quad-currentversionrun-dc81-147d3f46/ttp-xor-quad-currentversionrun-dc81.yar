rule TTP_XOR_QUAD_CurrentVersionRun_dc81 {
  strings:
    $key_dc81 = { 8f ee [2] ab e0 [2] 80 cc [2] ae ee [2] ba f5 [2] b5 ef [2] ab f2 [2] a9 f3 [2] b2 f5 [2] ae f2 [2] b2 dd }

  condition:
    any of them
}