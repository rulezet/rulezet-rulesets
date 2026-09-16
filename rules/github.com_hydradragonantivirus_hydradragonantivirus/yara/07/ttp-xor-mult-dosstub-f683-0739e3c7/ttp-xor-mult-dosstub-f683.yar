rule TTP_XOR_MULT_DOSStub_f683 {
  strings:
    $key_f683 = { a2 eb [2] d6 f3 [2] 91 f1 [2] d6 e0 [2] 98 ec [2] 94 e6 [2] 83 ed [2] 98 a3 [2] a5 }

  condition:
    any of them
}