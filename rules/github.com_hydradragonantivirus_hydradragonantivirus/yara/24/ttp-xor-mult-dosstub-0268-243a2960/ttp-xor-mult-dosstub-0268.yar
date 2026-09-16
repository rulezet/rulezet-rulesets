rule TTP_XOR_MULT_DOSStub_0268 {
  strings:
    $key_0268 = { 56 00 [2] 22 18 [2] 65 1a [2] 22 0b [2] 6c 07 [2] 60 0d [2] 77 06 [2] 6c 48 [2] 51 }

  condition:
    any of them
}