rule TTP_XOR_MULT_DOSStub_06f8 {
  strings:
    $key_06f8 = { 52 90 [2] 26 88 [2] 61 8a [2] 26 9b [2] 68 97 [2] 64 9d [2] 73 96 [2] 68 d8 [2] 55 }

  condition:
    any of them
}