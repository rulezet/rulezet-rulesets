rule TTP_XOR_QUAD_CurrentVersionRun_a298 {
  strings:
    $key_a298 = { f1 f7 [2] d5 f9 [2] fe d5 [2] d0 f7 [2] c4 ec [2] cb f6 [2] d5 eb [2] d7 ea [2] cc ec [2] d0 eb [2] cc c4 }

  condition:
    any of them
}