rule TTP_XOR_QUAD_CurrentVersionRun_a58c {
  strings:
    $key_a58c = { f6 e3 [2] d2 ed [2] f9 c1 [2] d7 e3 [2] c3 f8 [2] cc e2 [2] d2 ff [2] d0 fe [2] cb f8 [2] d7 ff [2] cb d0 }

  condition:
    any of them
}