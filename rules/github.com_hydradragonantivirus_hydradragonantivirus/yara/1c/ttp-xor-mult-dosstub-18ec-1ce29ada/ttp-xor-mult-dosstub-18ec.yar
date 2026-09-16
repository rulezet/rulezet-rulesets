rule TTP_XOR_MULT_DOSStub_18ec {
  strings:
    $key_18ec = { 4c 84 [2] 38 9c [2] 7f 9e [2] 38 8f [2] 76 83 [2] 7a 89 [2] 6d 82 [2] 76 cc [2] 4b }

  condition:
    any of them
}