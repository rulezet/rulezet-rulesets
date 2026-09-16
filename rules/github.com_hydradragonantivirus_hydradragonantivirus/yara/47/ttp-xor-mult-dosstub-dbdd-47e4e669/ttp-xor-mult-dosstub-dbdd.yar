rule TTP_XOR_MULT_DOSStub_dbdd {
  strings:
    $key_dbdd = { 8f b5 [2] fb ad [2] bc af [2] fb be [2] b5 b2 [2] b9 b8 [2] ae b3 [2] b5 fd [2] 88 }

  condition:
    any of them
}