rule TTP_XOR_MULT_DOSStub_0d7e {
  strings:
    $key_0d7e = { 59 16 [2] 2d 0e [2] 6a 0c [2] 2d 1d [2] 63 11 [2] 6f 1b [2] 78 10 [2] 63 5e [2] 5e }

  condition:
    any of them
}