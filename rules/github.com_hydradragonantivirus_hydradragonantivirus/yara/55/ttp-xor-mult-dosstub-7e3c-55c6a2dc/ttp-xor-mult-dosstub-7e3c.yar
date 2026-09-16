rule TTP_XOR_MULT_DOSStub_7e3c {
  strings:
    $key_7e3c = { 2a 54 [2] 5e 4c [2] 19 4e [2] 5e 5f [2] 10 53 [2] 1c 59 [2] 0b 52 [2] 10 1c [2] 2d }

  condition:
    any of them
}