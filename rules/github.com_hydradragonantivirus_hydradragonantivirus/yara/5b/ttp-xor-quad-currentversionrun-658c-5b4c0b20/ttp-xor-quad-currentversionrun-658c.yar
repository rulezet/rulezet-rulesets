rule TTP_XOR_QUAD_CurrentVersionRun_658c {
  strings:
    $key_658c = { 36 e3 [2] 12 ed [2] 39 c1 [2] 17 e3 [2] 03 f8 [2] 0c e2 [2] 12 ff [2] 10 fe [2] 0b f8 [2] 17 ff [2] 0b d0 }

  condition:
    any of them
}