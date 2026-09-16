rule TTP_XOR_MULT_DOSStub_0b9c {
  strings:
    $key_0b9c = { 5f f4 [2] 2b ec [2] 6c ee [2] 2b ff [2] 65 f3 [2] 69 f9 [2] 7e f2 [2] 65 bc [2] 58 }

  condition:
    any of them
}