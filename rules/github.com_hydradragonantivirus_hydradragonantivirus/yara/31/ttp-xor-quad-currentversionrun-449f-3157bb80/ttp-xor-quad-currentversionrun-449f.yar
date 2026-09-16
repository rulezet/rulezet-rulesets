rule TTP_XOR_QUAD_CurrentVersionRun_449f {
  strings:
    $key_449f = { 17 f0 [2] 33 fe [2] 18 d2 [2] 36 f0 [2] 22 eb [2] 2d f1 [2] 33 ec [2] 31 ed [2] 2a eb [2] 36 ec [2] 2a c3 }

  condition:
    any of them
}