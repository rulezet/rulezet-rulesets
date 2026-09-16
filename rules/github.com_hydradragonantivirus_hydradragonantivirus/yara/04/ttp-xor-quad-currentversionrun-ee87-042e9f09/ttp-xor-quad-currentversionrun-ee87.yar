rule TTP_XOR_QUAD_CurrentVersionRun_ee87 {
  strings:
    $key_ee87 = { bd e8 [2] 99 e6 [2] b2 ca [2] 9c e8 [2] 88 f3 [2] 87 e9 [2] 99 f4 [2] 9b f5 [2] 80 f3 [2] 9c f4 [2] 80 db }

  condition:
    any of them
}