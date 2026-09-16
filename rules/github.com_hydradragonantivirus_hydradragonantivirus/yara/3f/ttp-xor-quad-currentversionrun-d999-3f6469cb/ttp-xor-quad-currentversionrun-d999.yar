rule TTP_XOR_QUAD_CurrentVersionRun_d999 {
  strings:
    $key_d999 = { 8a f6 [2] ae f8 [2] 85 d4 [2] ab f6 [2] bf ed [2] b0 f7 [2] ae ea [2] ac eb [2] b7 ed [2] ab ea [2] b7 c5 }

  condition:
    any of them
}