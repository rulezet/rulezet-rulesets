rule TTP_XOR_MULT_DOSStub_501c {
  strings:
    $key_501c = { 04 74 [2] 70 6c [2] 37 6e [2] 70 7f [2] 3e 73 [2] 32 79 [2] 25 72 [2] 3e 3c [2] 03 }

  condition:
    any of them
}