rule TTP_XOR_MULT_DOSStub_e083 {
  strings:
    $key_e083 = { b4 eb [2] c0 f3 [2] 87 f1 [2] c0 e0 [2] 8e ec [2] 82 e6 [2] 95 ed [2] 8e a3 [2] b3 }

  condition:
    any of them
}