rule TTP_XOR_MULT_DOSStub_db51 {
  strings:
    $key_db51 = { 8f 39 [2] fb 21 [2] bc 23 [2] fb 32 [2] b5 3e [2] b9 34 [2] ae 3f [2] b5 71 [2] 88 }

  condition:
    any of them
}