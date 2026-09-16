rule TTP_XOR_MULT_DOSStub_db01 {
  strings:
    $key_db01 = { 8f 69 [2] fb 71 [2] bc 73 [2] fb 62 [2] b5 6e [2] b9 64 [2] ae 6f [2] b5 21 [2] 88 }

  condition:
    any of them
}