rule TTP_XOR_MULT_DOSStub_f8cb {
  strings:
    $key_f8cb = { ac a3 [2] d8 bb [2] 9f b9 [2] d8 a8 [2] 96 a4 [2] 9a ae [2] 8d a5 [2] 96 eb [2] ab }

  condition:
    any of them
}