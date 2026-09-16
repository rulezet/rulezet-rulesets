rule TTP_XOR_MULT_DOSStub_3104 {
  strings:
    $key_3104 = { 65 6c [2] 11 74 [2] 56 76 [2] 11 67 [2] 5f 6b [2] 53 61 [2] 44 6a [2] 5f 24 [2] 62 }

  condition:
    any of them
}