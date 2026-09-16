rule TTP_XOR_MULT_DOSStub_cc1c {
  strings:
    $key_cc1c = { 98 74 [2] ec 6c [2] ab 6e [2] ec 7f [2] a2 73 [2] ae 79 [2] b9 72 [2] a2 3c [2] 9f }

  condition:
    any of them
}