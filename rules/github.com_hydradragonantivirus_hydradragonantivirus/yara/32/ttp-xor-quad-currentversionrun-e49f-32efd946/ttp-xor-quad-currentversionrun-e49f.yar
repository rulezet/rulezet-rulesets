rule TTP_XOR_QUAD_CurrentVersionRun_e49f {
  strings:
    $key_e49f = { b7 f0 [2] 93 fe [2] b8 d2 [2] 96 f0 [2] 82 eb [2] 8d f1 [2] 93 ec [2] 91 ed [2] 8a eb [2] 96 ec [2] 8a c3 }

  condition:
    any of them
}