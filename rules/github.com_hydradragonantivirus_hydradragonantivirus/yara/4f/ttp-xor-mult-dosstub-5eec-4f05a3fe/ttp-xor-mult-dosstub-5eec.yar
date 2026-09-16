rule TTP_XOR_MULT_DOSStub_5eec {
  strings:
    $key_5eec = { 0a 84 [2] 7e 9c [2] 39 9e [2] 7e 8f [2] 30 83 [2] 3c 89 [2] 2b 82 [2] 30 cc [2] 0d }

  condition:
    any of them
}