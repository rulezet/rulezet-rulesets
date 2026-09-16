rule TTP_XOR_MULT_DOSStub_e104 {
  strings:
    $key_e104 = { b5 6c [2] c1 74 [2] 86 76 [2] c1 67 [2] 8f 6b [2] 83 61 [2] 94 6a [2] 8f 24 [2] b2 }

  condition:
    any of them
}