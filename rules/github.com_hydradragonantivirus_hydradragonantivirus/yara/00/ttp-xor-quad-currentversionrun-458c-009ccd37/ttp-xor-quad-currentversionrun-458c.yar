rule TTP_XOR_QUAD_CurrentVersionRun_458c {
  strings:
    $key_458c = { 16 e3 [2] 32 ed [2] 19 c1 [2] 37 e3 [2] 23 f8 [2] 2c e2 [2] 32 ff [2] 30 fe [2] 2b f8 [2] 37 ff [2] 2b d0 }

  condition:
    any of them
}