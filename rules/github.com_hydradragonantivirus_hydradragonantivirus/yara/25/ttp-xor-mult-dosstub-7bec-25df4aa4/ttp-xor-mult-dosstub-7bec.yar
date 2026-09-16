rule TTP_XOR_MULT_DOSStub_7bec {
  strings:
    $key_7bec = { 2f 84 [2] 5b 9c [2] 1c 9e [2] 5b 8f [2] 15 83 [2] 19 89 [2] 0e 82 [2] 15 cc [2] 28 }

  condition:
    any of them
}