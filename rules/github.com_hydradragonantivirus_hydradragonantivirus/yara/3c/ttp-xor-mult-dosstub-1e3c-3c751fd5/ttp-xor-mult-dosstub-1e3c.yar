rule TTP_XOR_MULT_DOSStub_1e3c {
  strings:
    $key_1e3c = { 4a 54 [2] 3e 4c [2] 79 4e [2] 3e 5f [2] 70 53 [2] 7c 59 [2] 6b 52 [2] 70 1c [2] 4d }

  condition:
    any of them
}