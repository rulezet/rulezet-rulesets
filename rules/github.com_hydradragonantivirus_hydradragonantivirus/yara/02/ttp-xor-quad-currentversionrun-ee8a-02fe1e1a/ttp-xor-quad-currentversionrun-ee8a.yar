rule TTP_XOR_QUAD_CurrentVersionRun_ee8a {
  strings:
    $key_ee8a = { bd e5 [2] 99 eb [2] b2 c7 [2] 9c e5 [2] 88 fe [2] 87 e4 [2] 99 f9 [2] 9b f8 [2] 80 fe [2] 9c f9 [2] 80 d6 }

  condition:
    any of them
}