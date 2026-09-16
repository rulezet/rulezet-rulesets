rule TTP_XOR_MULT_DOSStub_db73 {
  strings:
    $key_db73 = { 8f 1b [2] fb 03 [2] bc 01 [2] fb 10 [2] b5 1c [2] b9 16 [2] ae 1d [2] b5 53 [2] 88 }

  condition:
    any of them
}