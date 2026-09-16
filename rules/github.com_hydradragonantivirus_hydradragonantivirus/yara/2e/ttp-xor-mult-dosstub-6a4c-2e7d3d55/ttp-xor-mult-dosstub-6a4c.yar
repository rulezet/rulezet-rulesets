rule TTP_XOR_MULT_DOSStub_6a4c {
  strings:
    $key_6a4c = { 3e 24 [2] 4a 3c [2] 0d 3e [2] 4a 2f [2] 04 23 [2] 08 29 [2] 1f 22 [2] 04 6c [2] 39 }

  condition:
    any of them
}