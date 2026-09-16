rule TTP_XOR_MULT_DOSStub_723c {
  strings:
    $key_723c = { 26 54 [2] 52 4c [2] 15 4e [2] 52 5f [2] 1c 53 [2] 10 59 [2] 07 52 [2] 1c 1c [2] 21 }

  condition:
    any of them
}