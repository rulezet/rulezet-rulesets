rule TTP_XOR_MULT_DOSStub_6f7c {
  strings:
    $key_6f7c = { 3b 14 [2] 4f 0c [2] 08 0e [2] 4f 1f [2] 01 13 [2] 0d 19 [2] 1a 12 [2] 01 5c [2] 3c }

  condition:
    any of them
}