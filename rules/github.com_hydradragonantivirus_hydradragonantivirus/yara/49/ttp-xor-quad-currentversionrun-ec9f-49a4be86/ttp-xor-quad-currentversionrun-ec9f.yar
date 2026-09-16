rule TTP_XOR_QUAD_CurrentVersionRun_ec9f {
  strings:
    $key_ec9f = { bf f0 [2] 9b fe [2] b0 d2 [2] 9e f0 [2] 8a eb [2] 85 f1 [2] 9b ec [2] 99 ed [2] 82 eb [2] 9e ec [2] 82 c3 }

  condition:
    any of them
}