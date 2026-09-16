rule TTP_XOR_MULT_DOSStub_2b9c {
  strings:
    $key_2b9c = { 7f f4 [2] 0b ec [2] 4c ee [2] 0b ff [2] 45 f3 [2] 49 f9 [2] 5e f2 [2] 45 bc [2] 78 }

  condition:
    any of them
}