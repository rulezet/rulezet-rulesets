rule TTP_XOR_MULT_DOSStub_34ec {
  strings:
    $key_34ec = { 60 84 [2] 14 9c [2] 53 9e [2] 14 8f [2] 5a 83 [2] 56 89 [2] 41 82 [2] 5a cc [2] 67 }

  condition:
    any of them
}