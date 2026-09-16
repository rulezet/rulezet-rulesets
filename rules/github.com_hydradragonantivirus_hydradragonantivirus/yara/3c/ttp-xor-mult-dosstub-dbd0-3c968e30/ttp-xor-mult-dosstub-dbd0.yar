rule TTP_XOR_MULT_DOSStub_dbd0 {
  strings:
    $key_dbd0 = { 8f b8 [2] fb a0 [2] bc a2 [2] fb b3 [2] b5 bf [2] b9 b5 [2] ae be [2] b5 f0 [2] 88 }

  condition:
    any of them
}