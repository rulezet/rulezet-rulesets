rule TTP_XOR_QUAD_CurrentVersionRun_c59f {
  strings:
    $key_c59f = { 96 f0 [2] b2 fe [2] 99 d2 [2] b7 f0 [2] a3 eb [2] ac f1 [2] b2 ec [2] b0 ed [2] ab eb [2] b7 ec [2] ab c3 }

  condition:
    any of them
}