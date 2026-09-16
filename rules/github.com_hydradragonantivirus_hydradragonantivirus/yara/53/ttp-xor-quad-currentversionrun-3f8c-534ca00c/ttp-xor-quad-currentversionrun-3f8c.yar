rule TTP_XOR_QUAD_CurrentVersionRun_3f8c {
  strings:
    $key_3f8c = { 6c e3 [2] 48 ed [2] 63 c1 [2] 4d e3 [2] 59 f8 [2] 56 e2 [2] 48 ff [2] 4a fe [2] 51 f8 [2] 4d ff [2] 51 d0 }

  condition:
    any of them
}