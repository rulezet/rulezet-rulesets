rule TTP_XOR_MULT_DOSStub_db71 {
  strings:
    $key_db71 = { 8f 19 [2] fb 01 [2] bc 03 [2] fb 12 [2] b5 1e [2] b9 14 [2] ae 1f [2] b5 51 [2] 88 }

  condition:
    any of them
}