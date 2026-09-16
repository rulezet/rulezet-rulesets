rule TTP_XOR_MULT_DOSStub_db85 {
  strings:
    $key_db85 = { 8f ed [2] fb f5 [2] bc f7 [2] fb e6 [2] b5 ea [2] b9 e0 [2] ae eb [2] b5 a5 [2] 88 }

  condition:
    any of them
}