rule TTP_XOR_MULT_DOSStub_554c {
  strings:
    $key_554c = { 01 24 [2] 75 3c [2] 32 3e [2] 75 2f [2] 3b 23 [2] 37 29 [2] 20 22 [2] 3b 6c [2] 06 }

  condition:
    any of them
}