rule TTP_XOR_MULT_DOSStub_0a1c {
  strings:
    $key_0a1c = { 5e 74 [2] 2a 6c [2] 6d 6e [2] 2a 7f [2] 64 73 [2] 68 79 [2] 7f 72 [2] 64 3c [2] 59 }

  condition:
    any of them
}