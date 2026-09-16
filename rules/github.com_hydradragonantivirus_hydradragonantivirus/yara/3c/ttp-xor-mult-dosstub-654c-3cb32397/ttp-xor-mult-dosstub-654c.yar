rule TTP_XOR_MULT_DOSStub_654c {
  strings:
    $key_654c = { 31 24 [2] 45 3c [2] 02 3e [2] 45 2f [2] 0b 23 [2] 07 29 [2] 10 22 [2] 0b 6c [2] 36 }

  condition:
    any of them
}