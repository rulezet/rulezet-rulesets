rule TTP_XOR_QUAD_CurrentVersionRun_ee86 {
  strings:
    $key_ee86 = { bd e9 [2] 99 e7 [2] b2 cb [2] 9c e9 [2] 88 f2 [2] 87 e8 [2] 99 f5 [2] 9b f4 [2] 80 f2 [2] 9c f5 [2] 80 da }

  condition:
    any of them
}