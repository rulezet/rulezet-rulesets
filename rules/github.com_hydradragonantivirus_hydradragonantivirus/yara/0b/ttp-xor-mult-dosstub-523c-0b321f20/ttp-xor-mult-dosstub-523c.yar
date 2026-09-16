rule TTP_XOR_MULT_DOSStub_523c {
  strings:
    $key_523c = { 06 54 [2] 72 4c [2] 35 4e [2] 72 5f [2] 3c 53 [2] 30 59 [2] 27 52 [2] 3c 1c [2] 01 }

  condition:
    any of them
}