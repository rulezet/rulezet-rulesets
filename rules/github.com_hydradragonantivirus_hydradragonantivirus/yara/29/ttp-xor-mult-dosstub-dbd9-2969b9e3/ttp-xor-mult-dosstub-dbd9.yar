rule TTP_XOR_MULT_DOSStub_dbd9 {
  strings:
    $key_dbd9 = { 8f b1 [2] fb a9 [2] bc ab [2] fb ba [2] b5 b6 [2] b9 bc [2] ae b7 [2] b5 f9 [2] 88 }

  condition:
    any of them
}