rule TTP_XOR_MULT_DOSStub_e509 {
  strings:
    $key_e509 = { b1 61 [2] c5 79 [2] 82 7b [2] c5 6a [2] 8b 66 [2] 87 6c [2] 90 67 [2] 8b 29 [2] b6 }

  condition:
    any of them
}