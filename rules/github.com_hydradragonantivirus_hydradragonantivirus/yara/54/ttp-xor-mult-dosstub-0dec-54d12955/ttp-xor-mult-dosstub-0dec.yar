rule TTP_XOR_MULT_DOSStub_0dec {
  strings:
    $key_0dec = { 59 84 [2] 2d 9c [2] 6a 9e [2] 2d 8f [2] 63 83 [2] 6f 89 [2] 78 82 [2] 63 cc [2] 5e }

  condition:
    any of them
}