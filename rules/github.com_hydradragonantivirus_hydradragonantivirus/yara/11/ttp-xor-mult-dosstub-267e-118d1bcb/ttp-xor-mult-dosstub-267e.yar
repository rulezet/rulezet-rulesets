rule TTP_XOR_MULT_DOSStub_267e {
  strings:
    $key_267e = { 72 16 [2] 06 0e [2] 41 0c [2] 06 1d [2] 48 11 [2] 44 1b [2] 53 10 [2] 48 5e [2] 75 }

  condition:
    any of them
}