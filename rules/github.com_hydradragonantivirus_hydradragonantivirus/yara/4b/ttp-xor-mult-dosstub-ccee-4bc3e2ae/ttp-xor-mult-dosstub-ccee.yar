rule TTP_XOR_MULT_DOSStub_ccee {
  strings:
    $key_ccee = { 98 86 [2] ec 9e [2] ab 9c [2] ec 8d [2] a2 81 [2] ae 8b [2] b9 80 [2] a2 ce [2] 9f }

  condition:
    any of them
}