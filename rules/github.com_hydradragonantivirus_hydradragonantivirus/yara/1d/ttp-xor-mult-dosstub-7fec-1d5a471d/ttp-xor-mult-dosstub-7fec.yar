rule TTP_XOR_MULT_DOSStub_7fec {
  strings:
    $key_7fec = { 2b 84 [2] 5f 9c [2] 18 9e [2] 5f 8f [2] 11 83 [2] 1d 89 [2] 0a 82 [2] 11 cc [2] 2c }

  condition:
    any of them
}