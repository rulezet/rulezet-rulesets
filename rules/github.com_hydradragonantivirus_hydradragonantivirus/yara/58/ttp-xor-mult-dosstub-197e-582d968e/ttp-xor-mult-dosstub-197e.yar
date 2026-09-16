rule TTP_XOR_MULT_DOSStub_197e {
  strings:
    $key_197e = { 4d 16 [2] 39 0e [2] 7e 0c [2] 39 1d [2] 77 11 [2] 7b 1b [2] 6c 10 [2] 77 5e [2] 4a }

  condition:
    any of them
}