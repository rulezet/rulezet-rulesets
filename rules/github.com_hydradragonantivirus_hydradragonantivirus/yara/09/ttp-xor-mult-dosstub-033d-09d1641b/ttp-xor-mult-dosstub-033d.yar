rule TTP_XOR_MULT_DOSStub_033d {
  strings:
    $key_033d = { 57 55 [2] 23 4d [2] 64 4f [2] 23 5e [2] 6d 52 [2] 61 58 [2] 76 53 [2] 6d 1d [2] 50 }

  condition:
    any of them
}