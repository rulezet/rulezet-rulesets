rule TTP_XOR_MULT_DOSStub_7cec {
  strings:
    $key_7cec = { 28 84 [2] 5c 9c [2] 1b 9e [2] 5c 8f [2] 12 83 [2] 1e 89 [2] 09 82 [2] 12 cc [2] 2f }

  condition:
    any of them
}