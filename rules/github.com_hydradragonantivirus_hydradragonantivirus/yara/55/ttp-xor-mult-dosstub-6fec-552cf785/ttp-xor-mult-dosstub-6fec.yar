rule TTP_XOR_MULT_DOSStub_6fec {
  strings:
    $key_6fec = { 3b 84 [2] 4f 9c [2] 08 9e [2] 4f 8f [2] 01 83 [2] 0d 89 [2] 1a 82 [2] 01 cc [2] 3c }

  condition:
    any of them
}