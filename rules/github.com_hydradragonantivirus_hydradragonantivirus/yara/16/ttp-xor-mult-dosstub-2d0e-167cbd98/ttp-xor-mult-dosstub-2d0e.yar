rule TTP_XOR_MULT_DOSStub_2d0e {
  strings:
    $key_2d0e = { 79 66 [2] 0d 7e [2] 4a 7c [2] 0d 6d [2] 43 61 [2] 4f 6b [2] 58 60 [2] 43 2e [2] 7e }

  condition:
    any of them
}