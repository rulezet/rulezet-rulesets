rule TTP_XOR_MULT_DOSStub_c283 {
  strings:
    $key_c283 = { 96 eb [2] e2 f3 [2] a5 f1 [2] e2 e0 [2] ac ec [2] a0 e6 [2] b7 ed [2] ac a3 [2] 91 }

  condition:
    any of them
}