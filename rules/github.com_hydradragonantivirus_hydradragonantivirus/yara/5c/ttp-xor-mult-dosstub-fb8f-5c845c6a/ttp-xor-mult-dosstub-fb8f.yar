rule TTP_XOR_MULT_DOSStub_fb8f {
  strings:
    $key_fb8f = { af e7 [2] db ff [2] 9c fd [2] db ec [2] 95 e0 [2] 99 ea [2] 8e e1 [2] 95 af [2] a8 }

  condition:
    any of them
}