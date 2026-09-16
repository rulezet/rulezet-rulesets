rule TTP_XOR_MULT_DOSStub_39ec {
  strings:
    $key_39ec = { 6d 84 [2] 19 9c [2] 5e 9e [2] 19 8f [2] 57 83 [2] 5b 89 [2] 4c 82 [2] 57 cc [2] 6a }

  condition:
    any of them
}