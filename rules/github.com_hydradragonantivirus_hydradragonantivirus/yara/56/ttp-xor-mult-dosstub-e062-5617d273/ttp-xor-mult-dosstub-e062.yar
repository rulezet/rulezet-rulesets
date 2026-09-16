rule TTP_XOR_MULT_DOSStub_e062 {
  strings:
    $key_e062 = { b4 0a [2] c0 12 [2] 87 10 [2] c0 01 [2] 8e 0d [2] 82 07 [2] 95 0c [2] 8e 42 [2] b3 }

  condition:
    any of them
}