rule TTP_XOR_QUAD_CurrentVersionRun_d99f {
  strings:
    $key_d99f = { 8a f0 [2] ae fe [2] 85 d2 [2] ab f0 [2] bf eb [2] b0 f1 [2] ae ec [2] ac ed [2] b7 eb [2] ab ec [2] b7 c3 }

  condition:
    any of them
}