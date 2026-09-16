rule TTP_XOR_MULT_DOSStub_db61 {
  strings:
    $key_db61 = { 8f 09 [2] fb 11 [2] bc 13 [2] fb 02 [2] b5 0e [2] b9 04 [2] ae 0f [2] b5 41 [2] 88 }

  condition:
    any of them
}