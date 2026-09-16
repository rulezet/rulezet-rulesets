rule TTP_XOR_MULT_DOSStub_1e1c {
  strings:
    $key_1e1c = { 4a 74 [2] 3e 6c [2] 79 6e [2] 3e 7f [2] 70 73 [2] 7c 79 [2] 6b 72 [2] 70 3c [2] 4d }

  condition:
    any of them
}