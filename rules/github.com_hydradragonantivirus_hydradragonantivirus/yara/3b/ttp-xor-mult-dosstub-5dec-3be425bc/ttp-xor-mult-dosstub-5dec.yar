rule TTP_XOR_MULT_DOSStub_5dec {
  strings:
    $key_5dec = { 09 84 [2] 7d 9c [2] 3a 9e [2] 7d 8f [2] 33 83 [2] 3f 89 [2] 28 82 [2] 33 cc [2] 0e }

  condition:
    any of them
}