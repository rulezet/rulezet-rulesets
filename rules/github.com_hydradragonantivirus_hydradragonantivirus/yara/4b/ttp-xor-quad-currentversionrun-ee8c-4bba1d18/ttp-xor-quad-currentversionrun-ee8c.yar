rule TTP_XOR_QUAD_CurrentVersionRun_ee8c {
  strings:
    $key_ee8c = { bd e3 [2] 99 ed [2] b2 c1 [2] 9c e3 [2] 88 f8 [2] 87 e2 [2] 99 ff [2] 9b fe [2] 80 f8 [2] 9c ff [2] 80 d0 }

  condition:
    any of them
}