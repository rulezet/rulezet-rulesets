rule TTP_XOR_MULT_DOSStub_0d1c {
  strings:
    $key_0d1c = { 59 74 [2] 2d 6c [2] 6a 6e [2] 2d 7f [2] 63 73 [2] 6f 79 [2] 78 72 [2] 63 3c [2] 5e }

  condition:
    any of them
}