rule TTP_XOR_MULT_DOSStub_6f3c {
  strings:
    $key_6f3c = { 3b 54 [2] 4f 4c [2] 08 4e [2] 4f 5f [2] 01 53 [2] 0d 59 [2] 1a 52 [2] 01 1c [2] 3c }

  condition:
    any of them
}