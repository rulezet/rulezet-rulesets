rule TTP_XOR_MULT_DOSStub_cc83 {
  strings:
    $key_cc83 = { 98 eb [2] ec f3 [2] ab f1 [2] ec e0 [2] a2 ec [2] ae e6 [2] b9 ed [2] a2 a3 [2] 9f }

  condition:
    any of them
}