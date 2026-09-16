rule TTP_XOR_MULT_DOSStub_0218 {
  strings:
    $key_0218 = { 56 70 [2] 22 68 [2] 65 6a [2] 22 7b [2] 6c 77 [2] 60 7d [2] 77 76 [2] 6c 38 [2] 51 }

  condition:
    any of them
}