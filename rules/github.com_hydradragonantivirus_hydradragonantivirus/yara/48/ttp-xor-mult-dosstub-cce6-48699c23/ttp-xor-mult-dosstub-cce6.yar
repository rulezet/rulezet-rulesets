rule TTP_XOR_MULT_DOSStub_cce6 {
  strings:
    $key_cce6 = { 98 8e [2] ec 96 [2] ab 94 [2] ec 85 [2] a2 89 [2] ae 83 [2] b9 88 [2] a2 c6 [2] 9f }

  condition:
    any of them
}