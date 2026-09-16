rule TTP_XOR_QUAD_CurrentVersionRun_1c9f {
  strings:
    $key_1c9f = { 4f f0 [2] 6b fe [2] 40 d2 [2] 6e f0 [2] 7a eb [2] 75 f1 [2] 6b ec [2] 69 ed [2] 72 eb [2] 6e ec [2] 72 c3 }

  condition:
    any of them
}