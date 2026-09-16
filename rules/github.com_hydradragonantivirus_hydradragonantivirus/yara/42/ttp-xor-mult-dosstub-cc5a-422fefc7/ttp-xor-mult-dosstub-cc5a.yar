rule TTP_XOR_MULT_DOSStub_cc5a {
  strings:
    $key_cc5a = { 98 32 [2] ec 2a [2] ab 28 [2] ec 39 [2] a2 35 [2] ae 3f [2] b9 34 [2] a2 7a [2] 9f }

  condition:
    any of them
}