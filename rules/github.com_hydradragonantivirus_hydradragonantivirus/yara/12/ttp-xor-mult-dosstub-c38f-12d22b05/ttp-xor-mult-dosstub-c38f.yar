rule TTP_XOR_MULT_DOSStub_c38f {
  strings:
    $key_c38f = { 97 e7 [2] e3 ff [2] a4 fd [2] e3 ec [2] ad e0 [2] a1 ea [2] b6 e1 [2] ad af [2] 90 }

  condition:
    any of them
}