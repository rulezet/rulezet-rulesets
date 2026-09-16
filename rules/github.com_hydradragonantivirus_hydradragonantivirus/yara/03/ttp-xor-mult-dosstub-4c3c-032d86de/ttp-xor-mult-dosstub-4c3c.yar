rule TTP_XOR_MULT_DOSStub_4c3c {
  strings:
    $key_4c3c = { 18 54 [2] 6c 4c [2] 2b 4e [2] 6c 5f [2] 22 53 [2] 2e 59 [2] 39 52 [2] 22 1c [2] 1f }

  condition:
    any of them
}