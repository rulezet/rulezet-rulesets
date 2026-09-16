rule TTP_XOR_MULT_DOSStub_ccf4 {
  strings:
    $key_ccf4 = { 98 9c [2] ec 84 [2] ab 86 [2] ec 97 [2] a2 9b [2] ae 91 [2] b9 9a [2] a2 d4 [2] 9f }

  condition:
    any of them
}