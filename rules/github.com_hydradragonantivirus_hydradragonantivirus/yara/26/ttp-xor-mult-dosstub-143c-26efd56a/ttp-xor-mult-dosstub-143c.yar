rule TTP_XOR_MULT_DOSStub_143c {
  strings:
    $key_143c = { 40 54 [2] 34 4c [2] 73 4e [2] 34 5f [2] 7a 53 [2] 76 59 [2] 61 52 [2] 7a 1c [2] 47 }

  condition:
    any of them
}