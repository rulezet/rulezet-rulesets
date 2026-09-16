rule TTP_XOR_MULT_DOSStub_e059 {
  strings:
    $key_e059 = { b4 31 [2] c0 29 [2] 87 2b [2] c0 3a [2] 8e 36 [2] 82 3c [2] 95 37 [2] 8e 79 [2] b3 }

  condition:
    any of them
}