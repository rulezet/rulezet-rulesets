rule TTP_XOR_MULT_DOSStub_3134 {
  strings:
    $key_3134 = { 65 5c [2] 11 44 [2] 56 46 [2] 11 57 [2] 5f 5b [2] 53 51 [2] 44 5a [2] 5f 14 [2] 62 }

  condition:
    any of them
}