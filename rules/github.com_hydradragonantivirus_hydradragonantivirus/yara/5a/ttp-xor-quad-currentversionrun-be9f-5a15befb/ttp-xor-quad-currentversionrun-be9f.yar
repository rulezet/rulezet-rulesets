rule TTP_XOR_QUAD_CurrentVersionRun_be9f {
  strings:
    $key_be9f = { ed f0 [2] c9 fe [2] e2 d2 [2] cc f0 [2] d8 eb [2] d7 f1 [2] c9 ec [2] cb ed [2] d0 eb [2] cc ec [2] d0 c3 }

  condition:
    any of them
}