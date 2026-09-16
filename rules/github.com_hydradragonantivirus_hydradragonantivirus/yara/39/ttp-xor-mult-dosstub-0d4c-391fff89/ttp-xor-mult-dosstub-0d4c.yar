rule TTP_XOR_MULT_DOSStub_0d4c {
  strings:
    $key_0d4c = { 59 24 [2] 2d 3c [2] 6a 3e [2] 2d 2f [2] 63 23 [2] 6f 29 [2] 78 22 [2] 63 6c [2] 5e }

  condition:
    any of them
}