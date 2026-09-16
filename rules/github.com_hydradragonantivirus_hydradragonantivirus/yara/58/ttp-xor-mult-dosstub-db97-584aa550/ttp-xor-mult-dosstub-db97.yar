rule TTP_XOR_MULT_DOSStub_db97 {
  strings:
    $key_db97 = { 8f ff [2] fb e7 [2] bc e5 [2] fb f4 [2] b5 f8 [2] b9 f2 [2] ae f9 [2] b5 b7 [2] 88 }

  condition:
    any of them
}