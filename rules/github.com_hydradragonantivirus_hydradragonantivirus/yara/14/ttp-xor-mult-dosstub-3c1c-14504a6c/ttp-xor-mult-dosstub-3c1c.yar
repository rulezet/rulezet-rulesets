rule TTP_XOR_MULT_DOSStub_3c1c {
  strings:
    $key_3c1c = { 68 74 [2] 1c 6c [2] 5b 6e [2] 1c 7f [2] 52 73 [2] 5e 79 [2] 49 72 [2] 52 3c [2] 6f }

  condition:
    any of them
}