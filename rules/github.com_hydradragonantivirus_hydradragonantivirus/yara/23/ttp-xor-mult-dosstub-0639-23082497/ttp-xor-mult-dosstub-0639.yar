rule TTP_XOR_MULT_DOSStub_0639 {
  strings:
    $key_0639 = { 52 51 [2] 26 49 [2] 61 4b [2] 26 5a [2] 68 56 [2] 64 5c [2] 73 57 [2] 68 19 [2] 55 }

  condition:
    any of them
}