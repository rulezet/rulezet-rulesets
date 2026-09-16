rule TTP_XOR_MULT_DOSStub_31e5 {
  strings:
    $key_31e5 = { 65 8d [2] 11 95 [2] 56 97 [2] 11 86 [2] 5f 8a [2] 53 80 [2] 44 8b [2] 5f c5 [2] 62 }

  condition:
    any of them
}