rule TTP_XOR_MULT_DOSStub_7f6d {
  strings:
    $key_7f6d = { 2b 05 [2] 5f 1d [2] 18 1f [2] 5f 0e [2] 11 02 [2] 1d 08 [2] 0a 03 [2] 11 4d [2] 2c }

  condition:
    any of them
}