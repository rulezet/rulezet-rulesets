rule TTP_XOR_QUAD_CurrentVersionRun_dbb3 {
  strings:
    $key_dbb3 = { 88 dc [2] ac d2 [2] 87 fe [2] a9 dc [2] bd c7 [2] b2 dd [2] ac c0 [2] ae c1 [2] b5 c7 [2] a9 c0 [2] b5 ef }

  condition:
    any of them
}