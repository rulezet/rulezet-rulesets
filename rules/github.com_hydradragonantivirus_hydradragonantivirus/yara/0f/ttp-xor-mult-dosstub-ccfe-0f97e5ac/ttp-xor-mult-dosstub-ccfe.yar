rule TTP_XOR_MULT_DOSStub_ccfe {
  strings:
    $key_ccfe = { 98 96 [2] ec 8e [2] ab 8c [2] ec 9d [2] a2 91 [2] ae 9b [2] b9 90 [2] a2 de [2] 9f }

  condition:
    any of them
}