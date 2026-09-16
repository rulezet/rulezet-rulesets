rule TTP_XOR_MULT_DOSStub_1cec {
  strings:
    $key_1cec = { 48 84 [2] 3c 9c [2] 7b 9e [2] 3c 8f [2] 72 83 [2] 7e 89 [2] 69 82 [2] 72 cc [2] 4f }

  condition:
    any of them
}