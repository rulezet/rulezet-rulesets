rule TTP_XOR_QUAD_CurrentVersionRun_058c {
  strings:
    $key_058c = { 56 e3 [2] 72 ed [2] 59 c1 [2] 77 e3 [2] 63 f8 [2] 6c e2 [2] 72 ff [2] 70 fe [2] 6b f8 [2] 77 ff [2] 6b d0 }

  condition:
    any of them
}