rule TTP_XOR_MULT_DOSStub_6f6d {
  strings:
    $key_6f6d = { 3b 05 [2] 4f 1d [2] 08 1f [2] 4f 0e [2] 01 02 [2] 0d 08 [2] 1a 03 [2] 01 4d [2] 3c }

  condition:
    any of them
}