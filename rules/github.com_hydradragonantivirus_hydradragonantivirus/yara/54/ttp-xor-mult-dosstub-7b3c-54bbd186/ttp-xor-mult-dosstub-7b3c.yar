rule TTP_XOR_MULT_DOSStub_7b3c {
  strings:
    $key_7b3c = { 2f 54 [2] 5b 4c [2] 1c 4e [2] 5b 5f [2] 15 53 [2] 19 59 [2] 0e 52 [2] 15 1c [2] 28 }

  condition:
    any of them
}