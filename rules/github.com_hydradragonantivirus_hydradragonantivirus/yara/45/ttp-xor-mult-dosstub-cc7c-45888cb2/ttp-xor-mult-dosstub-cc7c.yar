rule TTP_XOR_MULT_DOSStub_cc7c {
  strings:
    $key_cc7c = { 98 14 [2] ec 0c [2] ab 0e [2] ec 1f [2] a2 13 [2] ae 19 [2] b9 12 [2] a2 5c [2] 9f }

  condition:
    any of them
}