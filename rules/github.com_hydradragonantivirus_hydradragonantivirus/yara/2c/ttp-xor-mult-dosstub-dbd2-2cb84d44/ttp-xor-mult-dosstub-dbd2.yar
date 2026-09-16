rule TTP_XOR_MULT_DOSStub_dbd2 {
  strings:
    $key_dbd2 = { 8f ba [2] fb a2 [2] bc a0 [2] fb b1 [2] b5 bd [2] b9 b7 [2] ae bc [2] b5 f2 [2] 88 }

  condition:
    any of them
}