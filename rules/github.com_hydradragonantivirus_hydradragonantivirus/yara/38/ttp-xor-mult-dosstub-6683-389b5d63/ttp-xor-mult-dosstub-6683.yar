rule TTP_XOR_MULT_DOSStub_6683 {
  strings:
    $key_6683 = { 32 eb [2] 46 f3 [2] 01 f1 [2] 46 e0 [2] 08 ec [2] 04 e6 [2] 13 ed [2] 08 a3 [2] 35 }

  condition:
    any of them
}