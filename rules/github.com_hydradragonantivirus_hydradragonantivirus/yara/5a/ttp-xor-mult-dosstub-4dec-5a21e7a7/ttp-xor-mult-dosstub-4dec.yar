rule TTP_XOR_MULT_DOSStub_4dec {
  strings:
    $key_4dec = { 19 84 [2] 6d 9c [2] 2a 9e [2] 6d 8f [2] 23 83 [2] 2f 89 [2] 38 82 [2] 23 cc [2] 1e }

  condition:
    any of them
}