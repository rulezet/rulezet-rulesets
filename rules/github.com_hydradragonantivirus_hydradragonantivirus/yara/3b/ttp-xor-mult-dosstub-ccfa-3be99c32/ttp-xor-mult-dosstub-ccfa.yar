rule TTP_XOR_MULT_DOSStub_ccfa {
  strings:
    $key_ccfa = { 98 92 [2] ec 8a [2] ab 88 [2] ec 99 [2] a2 95 [2] ae 9f [2] b9 94 [2] a2 da [2] 9f }

  condition:
    any of them
}