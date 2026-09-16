rule TTP_XOR_QUAD_CurrentVersionRun_dc86 {
  strings:
    $key_dc86 = { 8f e9 [2] ab e7 [2] 80 cb [2] ae e9 [2] ba f2 [2] b5 e8 [2] ab f5 [2] a9 f4 [2] b2 f2 [2] ae f5 [2] b2 da }

  condition:
    any of them
}