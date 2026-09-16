rule TTP_XOR_MULT_DOSStub_cc1a {
  strings:
    $key_cc1a = { 98 72 [2] ec 6a [2] ab 68 [2] ec 79 [2] a2 75 [2] ae 7f [2] b9 74 [2] a2 3a [2] 9f }

  condition:
    any of them
}