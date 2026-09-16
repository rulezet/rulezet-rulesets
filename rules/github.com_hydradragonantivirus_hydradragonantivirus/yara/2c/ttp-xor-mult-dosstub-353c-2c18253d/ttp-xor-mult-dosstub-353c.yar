rule TTP_XOR_MULT_DOSStub_353c {
  strings:
    $key_353c = { 61 54 [2] 15 4c [2] 52 4e [2] 15 5f [2] 5b 53 [2] 57 59 [2] 40 52 [2] 5b 1c [2] 66 }

  condition:
    any of them
}