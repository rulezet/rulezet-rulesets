rule TTP_XOR_MULT_DOSStub_ccf9 {
  strings:
    $key_ccf9 = { 98 91 [2] ec 89 [2] ab 8b [2] ec 9a [2] a2 96 [2] ae 9c [2] b9 97 [2] a2 d9 [2] 9f }

  condition:
    any of them
}