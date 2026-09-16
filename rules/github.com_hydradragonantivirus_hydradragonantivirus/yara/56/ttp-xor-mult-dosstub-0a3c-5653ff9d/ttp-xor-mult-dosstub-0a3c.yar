rule TTP_XOR_MULT_DOSStub_0a3c {
  strings:
    $key_0a3c = { 5e 54 [2] 2a 4c [2] 6d 4e [2] 2a 5f [2] 64 53 [2] 68 59 [2] 7f 52 [2] 64 1c [2] 59 }

  condition:
    any of them
}