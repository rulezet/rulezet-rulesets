rule TTP_XOR_MULT_DOSStub_392c {
  strings:
    $key_392c = { 6d 44 [2] 19 5c [2] 5e 5e [2] 19 4f [2] 57 43 [2] 5b 49 [2] 4c 42 [2] 57 0c [2] 6a }

  condition:
    any of them
}