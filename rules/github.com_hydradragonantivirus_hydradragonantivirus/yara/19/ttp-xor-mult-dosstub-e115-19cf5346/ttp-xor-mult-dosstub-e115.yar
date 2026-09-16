rule TTP_XOR_MULT_DOSStub_e115 {
  strings:
    $key_e115 = { b5 7d [2] c1 65 [2] 86 67 [2] c1 76 [2] 8f 7a [2] 83 70 [2] 94 7b [2] 8f 35 [2] b2 }

  condition:
    any of them
}