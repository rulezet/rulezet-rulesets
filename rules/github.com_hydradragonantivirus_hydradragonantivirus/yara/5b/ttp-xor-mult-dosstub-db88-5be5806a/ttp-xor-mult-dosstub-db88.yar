rule TTP_XOR_MULT_DOSStub_db88 {
  strings:
    $key_db88 = { 8f e0 [2] fb f8 [2] bc fa [2] fb eb [2] b5 e7 [2] b9 ed [2] ae e6 [2] b5 a8 [2] 88 }

  condition:
    any of them
}