rule TTP_XOR_MULT_DOSStub_dbd1 {
  strings:
    $key_dbd1 = { 8f b9 [2] fb a1 [2] bc a3 [2] fb b2 [2] b5 be [2] b9 b4 [2] ae bf [2] b5 f1 [2] 88 }

  condition:
    any of them
}