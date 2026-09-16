rule TTP_XOR_MULT_DOSStub_dbd8 {
  strings:
    $key_dbd8 = { 8f b0 [2] fb a8 [2] bc aa [2] fb bb [2] b5 b7 [2] b9 bd [2] ae b6 [2] b5 f8 [2] 88 }

  condition:
    any of them
}