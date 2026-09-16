rule TTP_XOR_QUAD_CurrentVersionRun_a29f {
  strings:
    $key_a29f = { f1 f0 [2] d5 fe [2] fe d2 [2] d0 f0 [2] c4 eb [2] cb f1 [2] d5 ec [2] d7 ed [2] cc eb [2] d0 ec [2] cc c3 }

  condition:
    any of them
}