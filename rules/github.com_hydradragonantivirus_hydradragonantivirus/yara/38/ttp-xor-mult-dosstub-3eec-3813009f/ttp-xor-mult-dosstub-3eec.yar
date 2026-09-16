rule TTP_XOR_MULT_DOSStub_3eec {
  strings:
    $key_3eec = { 6a 84 [2] 1e 9c [2] 59 9e [2] 1e 8f [2] 50 83 [2] 5c 89 [2] 4b 82 [2] 50 cc [2] 6d }

  condition:
    any of them
}