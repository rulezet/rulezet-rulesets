rule TTP_XOR_MULT_DOSStub_473c {
  strings:
    $key_473c = { 13 54 [2] 67 4c [2] 20 4e [2] 67 5f [2] 29 53 [2] 25 59 [2] 32 52 [2] 29 1c [2] 14 }

  condition:
    any of them
}