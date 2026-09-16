rule TTP_XOR_MULT_DOSStub_dbdb {
  strings:
    $key_dbdb = { 8f b3 [2] fb ab [2] bc a9 [2] fb b8 [2] b5 b4 [2] b9 be [2] ae b5 [2] b5 fb [2] 88 }

  condition:
    any of them
}