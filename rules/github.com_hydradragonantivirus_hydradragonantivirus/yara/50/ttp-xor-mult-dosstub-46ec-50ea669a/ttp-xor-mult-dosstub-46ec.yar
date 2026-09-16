rule TTP_XOR_MULT_DOSStub_46ec {
  strings:
    $key_46ec = { 12 84 [2] 66 9c [2] 21 9e [2] 66 8f [2] 28 83 [2] 24 89 [2] 33 82 [2] 28 cc [2] 15 }

  condition:
    any of them
}