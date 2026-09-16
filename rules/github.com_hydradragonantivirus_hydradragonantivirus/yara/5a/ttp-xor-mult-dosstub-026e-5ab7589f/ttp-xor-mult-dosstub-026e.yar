rule TTP_XOR_MULT_DOSStub_026e {
  strings:
    $key_026e = { 56 06 [2] 22 1e [2] 65 1c [2] 22 0d [2] 6c 01 [2] 60 0b [2] 77 00 [2] 6c 4e [2] 51 }

  condition:
    any of them
}