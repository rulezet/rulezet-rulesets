rule TTP_XOR_MULT_DOSStub_3c4c {
  strings:
    $key_3c4c = { 68 24 [2] 1c 3c [2] 5b 3e [2] 1c 2f [2] 52 23 [2] 5e 29 [2] 49 22 [2] 52 6c [2] 6f }

  condition:
    any of them
}