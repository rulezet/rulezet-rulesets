rule TTP_XOR_MULT_DOSStub_a2cb {
  strings:
    $key_a2cb = { f6 a3 [2] 82 bb [2] c5 b9 [2] 82 a8 [2] cc a4 [2] c0 ae [2] d7 a5 [2] cc eb [2] f1 }

  condition:
    any of them
}