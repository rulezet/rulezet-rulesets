rule TTP_XOR_MULT_DOSStub_dbba {
  strings:
    $key_dbba = { 8f d2 [2] fb ca [2] bc c8 [2] fb d9 [2] b5 d5 [2] b9 df [2] ae d4 [2] b5 9a [2] 88 }

  condition:
    any of them
}