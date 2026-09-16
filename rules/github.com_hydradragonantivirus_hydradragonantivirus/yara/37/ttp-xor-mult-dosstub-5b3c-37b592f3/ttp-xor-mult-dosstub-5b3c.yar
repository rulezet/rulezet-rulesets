rule TTP_XOR_MULT_DOSStub_5b3c {
  strings:
    $key_5b3c = { 0f 54 [2] 7b 4c [2] 3c 4e [2] 7b 5f [2] 35 53 [2] 39 59 [2] 2e 52 [2] 35 1c [2] 08 }

  condition:
    any of them
}