rule TTP_XOR_MULT_DOSStub_6b9c {
  strings:
    $key_6b9c = { 3f f4 [2] 4b ec [2] 0c ee [2] 4b ff [2] 05 f3 [2] 09 f9 [2] 1e f2 [2] 05 bc [2] 38 }

  condition:
    any of them
}