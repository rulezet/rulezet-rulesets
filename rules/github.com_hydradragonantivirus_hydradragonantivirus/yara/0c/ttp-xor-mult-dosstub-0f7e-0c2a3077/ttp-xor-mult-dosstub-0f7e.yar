rule TTP_XOR_MULT_DOSStub_0f7e {
  strings:
    $key_0f7e = { 5b 16 [2] 2f 0e [2] 68 0c [2] 2f 1d [2] 61 11 [2] 6d 1b [2] 7a 10 [2] 61 5e [2] 5c }

  condition:
    any of them
}