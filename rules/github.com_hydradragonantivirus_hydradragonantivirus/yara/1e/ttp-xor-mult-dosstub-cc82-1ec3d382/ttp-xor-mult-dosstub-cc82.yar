rule TTP_XOR_MULT_DOSStub_cc82 {
  strings:
    $key_cc82 = { 98 ea [2] ec f2 [2] ab f0 [2] ec e1 [2] a2 ed [2] ae e7 [2] b9 ec [2] a2 a2 [2] 9f }

  condition:
    any of them
}