rule TTP_XOR_QUAD_CurrentVersionRun_a59f {
  strings:
    $key_a59f = { f6 f0 [2] d2 fe [2] f9 d2 [2] d7 f0 [2] c3 eb [2] cc f1 [2] d2 ec [2] d0 ed [2] cb eb [2] d7 ec [2] cb c3 }

  condition:
    any of them
}