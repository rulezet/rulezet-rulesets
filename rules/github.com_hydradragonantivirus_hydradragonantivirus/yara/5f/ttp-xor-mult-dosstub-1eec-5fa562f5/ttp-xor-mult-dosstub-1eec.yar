rule TTP_XOR_MULT_DOSStub_1eec {
  strings:
    $key_1eec = { 4a 84 [2] 3e 9c [2] 79 9e [2] 3e 8f [2] 70 83 [2] 7c 89 [2] 6b 82 [2] 70 cc [2] 4d }

  condition:
    any of them
}