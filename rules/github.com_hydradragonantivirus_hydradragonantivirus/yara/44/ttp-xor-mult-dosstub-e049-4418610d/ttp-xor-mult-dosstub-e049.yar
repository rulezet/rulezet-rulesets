rule TTP_XOR_MULT_DOSStub_e049 {
  strings:
    $key_e049 = { b4 21 [2] c0 39 [2] 87 3b [2] c0 2a [2] 8e 26 [2] 82 2c [2] 95 27 [2] 8e 69 [2] b3 }

  condition:
    any of them
}