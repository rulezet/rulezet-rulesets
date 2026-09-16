rule TTP_XOR_MULT_DOSStub_730e {
  strings:
    $key_730e = { 27 66 [2] 53 7e [2] 14 7c [2] 53 6d [2] 1d 61 [2] 11 6b [2] 06 60 [2] 1d 2e [2] 20 }

  condition:
    any of them
}