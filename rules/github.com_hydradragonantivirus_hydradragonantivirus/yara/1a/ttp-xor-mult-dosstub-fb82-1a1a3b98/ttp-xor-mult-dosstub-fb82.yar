rule TTP_XOR_MULT_DOSStub_fb82 {
  strings:
    $key_fb82 = { af ea [2] db f2 [2] 9c f0 [2] db e1 [2] 95 ed [2] 99 e7 [2] 8e ec [2] 95 a2 [2] a8 }

  condition:
    any of them
}