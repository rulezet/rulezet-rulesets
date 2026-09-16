rule TTP_XOR_MULT_DOSStub_347e {
  strings:
    $key_347e = { 60 16 [2] 14 0e [2] 53 0c [2] 14 1d [2] 5a 11 [2] 56 1b [2] 41 10 [2] 5a 5e [2] 67 }

  condition:
    any of them
}