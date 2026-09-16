rule TTP_XOR_MULT_DOSStub_5e3c {
  strings:
    $key_5e3c = { 0a 54 [2] 7e 4c [2] 39 4e [2] 7e 5f [2] 30 53 [2] 3c 59 [2] 2b 52 [2] 30 1c [2] 0d }

  condition:
    any of them
}