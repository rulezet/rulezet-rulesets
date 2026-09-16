rule TTP_XOR_MULT_DOSStub_073c {
  strings:
    $key_073c = { 53 54 [2] 27 4c [2] 60 4e [2] 27 5f [2] 69 53 [2] 65 59 [2] 72 52 [2] 69 1c [2] 54 }

  condition:
    any of them
}