rule TTP_XOR_QUAD_CurrentVersionRun_c39f {
  strings:
    $key_c39f = { 90 f0 [2] b4 fe [2] 9f d2 [2] b1 f0 [2] a5 eb [2] aa f1 [2] b4 ec [2] b6 ed [2] ad eb [2] b1 ec [2] ad c3 }

  condition:
    any of them
}