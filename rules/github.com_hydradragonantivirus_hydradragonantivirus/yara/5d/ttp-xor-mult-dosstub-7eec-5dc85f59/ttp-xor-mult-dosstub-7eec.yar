rule TTP_XOR_MULT_DOSStub_7eec {
  strings:
    $key_7eec = { 2a 84 [2] 5e 9c [2] 19 9e [2] 5e 8f [2] 10 83 [2] 1c 89 [2] 0b 82 [2] 10 cc [2] 2d }

  condition:
    any of them
}