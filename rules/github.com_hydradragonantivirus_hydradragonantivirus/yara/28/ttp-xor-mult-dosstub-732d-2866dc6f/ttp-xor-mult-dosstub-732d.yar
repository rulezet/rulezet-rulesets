rule TTP_XOR_MULT_DOSStub_732d {
  strings:
    $key_732d = { 27 45 [2] 53 5d [2] 14 5f [2] 53 4e [2] 1d 42 [2] 11 48 [2] 06 43 [2] 1d 0d [2] 20 }

  condition:
    any of them
}