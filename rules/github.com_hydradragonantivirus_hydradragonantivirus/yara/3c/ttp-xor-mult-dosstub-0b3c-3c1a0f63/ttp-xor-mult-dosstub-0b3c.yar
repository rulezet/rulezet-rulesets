rule TTP_XOR_MULT_DOSStub_0b3c {
  strings:
    $key_0b3c = { 5f 54 [2] 2b 4c [2] 6c 4e [2] 2b 5f [2] 65 53 [2] 69 59 [2] 7e 52 [2] 65 1c [2] 58 }

  condition:
    any of them
}