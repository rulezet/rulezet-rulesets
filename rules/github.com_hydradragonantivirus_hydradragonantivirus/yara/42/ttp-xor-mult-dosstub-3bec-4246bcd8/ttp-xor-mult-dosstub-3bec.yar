rule TTP_XOR_MULT_DOSStub_3bec {
  strings:
    $key_3bec = { 6f 84 [2] 1b 9c [2] 5c 9e [2] 1b 8f [2] 55 83 [2] 59 89 [2] 4e 82 [2] 55 cc [2] 68 }

  condition:
    any of them
}