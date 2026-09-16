rule TTP_XOR_MULT_DOSStub_0e3c {
  strings:
    $key_0e3c = { 5a 54 [2] 2e 4c [2] 69 4e [2] 2e 5f [2] 60 53 [2] 6c 59 [2] 7b 52 [2] 60 1c [2] 5d }

  condition:
    any of them
}