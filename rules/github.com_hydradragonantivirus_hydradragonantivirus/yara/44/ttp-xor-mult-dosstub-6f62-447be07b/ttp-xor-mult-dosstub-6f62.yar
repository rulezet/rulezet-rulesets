rule TTP_XOR_MULT_DOSStub_6f62 {
  strings:
    $key_6f62 = { 3b 0a [2] 4f 12 [2] 08 10 [2] 4f 01 [2] 01 0d [2] 0d 07 [2] 1a 0c [2] 01 42 [2] 3c }

  condition:
    any of them
}