rule TTP_XOR_MULT_DOSStub_097e {
  strings:
    $key_097e = { 5d 16 [2] 29 0e [2] 6e 0c [2] 29 1d [2] 67 11 [2] 6b 1b [2] 7c 10 [2] 67 5e [2] 5a }

  condition:
    any of them
}