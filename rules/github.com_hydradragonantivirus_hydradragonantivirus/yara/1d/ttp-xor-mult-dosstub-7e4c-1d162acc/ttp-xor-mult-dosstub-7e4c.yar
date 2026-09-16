rule TTP_XOR_MULT_DOSStub_7e4c {
  strings:
    $key_7e4c = { 2a 24 [2] 5e 3c [2] 19 3e [2] 5e 2f [2] 10 23 [2] 1c 29 [2] 0b 22 [2] 10 6c [2] 2d }

  condition:
    any of them
}