rule TTP_XOR_MULT_DOSStub_e015 {
  strings:
    $key_e015 = { b4 7d [2] c0 65 [2] 87 67 [2] c0 76 [2] 8e 7a [2] 82 70 [2] 95 7b [2] 8e 35 [2] b3 }

  condition:
    any of them
}