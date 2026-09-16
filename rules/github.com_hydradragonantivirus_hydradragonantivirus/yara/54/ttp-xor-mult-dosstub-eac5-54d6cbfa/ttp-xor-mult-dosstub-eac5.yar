rule TTP_XOR_MULT_DOSStub_eac5 {
  strings:
    $key_eac5 = { be ad [2] ca b5 [2] 8d b7 [2] ca a6 [2] 84 aa [2] 88 a0 [2] 9f ab [2] 84 e5 [2] b9 }

  condition:
    any of them
}