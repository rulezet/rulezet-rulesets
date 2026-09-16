rule TTP_XOR_MULT_DOSStub_0683 {
  strings:
    $key_0683 = { 52 eb [2] 26 f3 [2] 61 f1 [2] 26 e0 [2] 68 ec [2] 64 e6 [2] 73 ed [2] 68 a3 [2] 55 }

  condition:
    any of them
}