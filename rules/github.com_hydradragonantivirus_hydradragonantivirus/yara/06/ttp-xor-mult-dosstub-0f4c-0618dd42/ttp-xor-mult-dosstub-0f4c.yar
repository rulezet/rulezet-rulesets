rule TTP_XOR_MULT_DOSStub_0f4c {
  strings:
    $key_0f4c = { 5b 24 [2] 2f 3c [2] 68 3e [2] 2f 2f [2] 61 23 [2] 6d 29 [2] 7a 22 [2] 61 6c [2] 5c }

  condition:
    any of them
}