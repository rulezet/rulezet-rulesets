rule TTP_XOR_MULT_DOSStub_6f3a {
  strings:
    $key_6f3a = { 3b 52 [2] 4f 4a [2] 08 48 [2] 4f 59 [2] 01 55 [2] 0d 5f [2] 1a 54 [2] 01 1a [2] 3c }

  condition:
    any of them
}