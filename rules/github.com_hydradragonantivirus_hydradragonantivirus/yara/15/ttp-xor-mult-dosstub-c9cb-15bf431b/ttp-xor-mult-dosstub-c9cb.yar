rule TTP_XOR_MULT_DOSStub_c9cb {
  strings:
    $key_c9cb = { 9d a3 [2] e9 bb [2] ae b9 [2] e9 a8 [2] a7 a4 [2] ab ae [2] bc a5 [2] a7 eb [2] 9a }

  condition:
    any of them
}