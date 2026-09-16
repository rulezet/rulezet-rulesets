rule TTP_XOR_MULT_DOSStub_321c {
  strings:
    $key_321c = { 66 74 [2] 12 6c [2] 55 6e [2] 12 7f [2] 5c 73 [2] 50 79 [2] 47 72 [2] 5c 3c [2] 61 }

  condition:
    any of them
}