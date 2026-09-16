rule TTP_XOR_MULT_DOSStub_e562 {
  strings:
    $key_e562 = { b1 0a [2] c5 12 [2] 82 10 [2] c5 01 [2] 8b 0d [2] 87 07 [2] 90 0c [2] 8b 42 [2] b6 }

  condition:
    any of them
}