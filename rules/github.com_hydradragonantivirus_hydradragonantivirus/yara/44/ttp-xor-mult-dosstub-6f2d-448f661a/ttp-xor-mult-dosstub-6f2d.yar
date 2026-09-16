rule TTP_XOR_MULT_DOSStub_6f2d {
  strings:
    $key_6f2d = { 3b 45 [2] 4f 5d [2] 08 5f [2] 4f 4e [2] 01 42 [2] 0d 48 [2] 1a 43 [2] 01 0d [2] 3c }

  condition:
    any of them
}