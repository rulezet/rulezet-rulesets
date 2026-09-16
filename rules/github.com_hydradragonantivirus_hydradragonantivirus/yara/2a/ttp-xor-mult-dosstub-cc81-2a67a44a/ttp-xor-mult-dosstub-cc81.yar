rule TTP_XOR_MULT_DOSStub_cc81 {
  strings:
    $key_cc81 = { 98 e9 [2] ec f1 [2] ab f3 [2] ec e2 [2] a2 ee [2] ae e4 [2] b9 ef [2] a2 a1 [2] 9f }

  condition:
    any of them
}