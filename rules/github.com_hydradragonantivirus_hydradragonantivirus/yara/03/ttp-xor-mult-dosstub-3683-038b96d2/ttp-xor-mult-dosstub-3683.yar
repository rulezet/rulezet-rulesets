rule TTP_XOR_MULT_DOSStub_3683 {
  strings:
    $key_3683 = { 62 eb [2] 16 f3 [2] 51 f1 [2] 16 e0 [2] 58 ec [2] 54 e6 [2] 43 ed [2] 58 a3 [2] 65 }

  condition:
    any of them
}