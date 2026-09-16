rule TTP_XOR_QUAD_CurrentVersionRun_b98c {
  strings:
    $key_b98c = { ea e3 [2] ce ed [2] e5 c1 [2] cb e3 [2] df f8 [2] d0 e2 [2] ce ff [2] cc fe [2] d7 f8 [2] cb ff [2] d7 d0 }

  condition:
    any of them
}