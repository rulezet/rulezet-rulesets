rule TTP_XOR_MULT_DOSStub_2783 {
  strings:
    $key_2783 = { 73 eb [2] 07 f3 [2] 40 f1 [2] 07 e0 [2] 49 ec [2] 45 e6 [2] 52 ed [2] 49 a3 [2] 74 }

  condition:
    any of them
}