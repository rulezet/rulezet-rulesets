rule TTP_XOR_MULT_DOSStub_bbec {
  strings:
    $key_bbec = { ef 84 [2] 9b 9c [2] dc 9e [2] 9b 8f [2] d5 83 [2] d9 89 [2] ce 82 [2] d5 cc [2] e8 }

  condition:
    any of them
}