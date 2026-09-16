rule TTP_XOR_QUAD_CurrentVersionRun_ef99 {
  strings:
    $key_ef99 = { bc f6 [2] 98 f8 [2] b3 d4 [2] 9d f6 [2] 89 ed [2] 86 f7 [2] 98 ea [2] 9a eb [2] 81 ed [2] 9d ea [2] 81 c5 }

  condition:
    any of them
}