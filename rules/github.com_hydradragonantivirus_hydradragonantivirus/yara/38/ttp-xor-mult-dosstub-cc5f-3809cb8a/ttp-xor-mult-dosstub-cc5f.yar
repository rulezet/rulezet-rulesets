rule TTP_XOR_MULT_DOSStub_cc5f {
  strings:
    $key_cc5f = { 98 37 [2] ec 2f [2] ab 2d [2] ec 3c [2] a2 30 [2] ae 3a [2] b9 31 [2] a2 7f [2] 9f }

  condition:
    any of them
}