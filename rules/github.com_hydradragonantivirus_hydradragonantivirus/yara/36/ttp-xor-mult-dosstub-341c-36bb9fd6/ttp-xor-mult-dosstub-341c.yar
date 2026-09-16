rule TTP_XOR_MULT_DOSStub_341c {
  strings:
    $key_341c = { 60 74 [2] 14 6c [2] 53 6e [2] 14 7f [2] 5a 73 [2] 56 79 [2] 41 72 [2] 5a 3c [2] 67 }

  condition:
    any of them
}