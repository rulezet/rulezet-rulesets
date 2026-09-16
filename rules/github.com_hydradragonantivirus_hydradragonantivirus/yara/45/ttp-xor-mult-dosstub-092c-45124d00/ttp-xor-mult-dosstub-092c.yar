rule TTP_XOR_MULT_DOSStub_092c {
  strings:
    $key_092c = { 5d 44 [2] 29 5c [2] 6e 5e [2] 29 4f [2] 67 43 [2] 6b 49 [2] 7c 42 [2] 67 0c [2] 5a }

  condition:
    any of them
}