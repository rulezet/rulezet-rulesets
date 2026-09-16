rule TTP_XOR_MULT_DOSStub_2aec {
  strings:
    $key_2aec = { 7e 84 [2] 0a 9c [2] 4d 9e [2] 0a 8f [2] 44 83 [2] 48 89 [2] 5f 82 [2] 44 cc [2] 79 }

  condition:
    any of them
}