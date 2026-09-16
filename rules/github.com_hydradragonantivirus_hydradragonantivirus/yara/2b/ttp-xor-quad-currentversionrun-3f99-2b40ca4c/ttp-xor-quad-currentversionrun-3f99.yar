rule TTP_XOR_QUAD_CurrentVersionRun_3f99 {
  strings:
    $key_3f99 = { 6c f6 [2] 48 f8 [2] 63 d4 [2] 4d f6 [2] 59 ed [2] 56 f7 [2] 48 ea [2] 4a eb [2] 51 ed [2] 4d ea [2] 51 c5 }

  condition:
    any of them
}