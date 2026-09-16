rule TTP_XOR_MULT_DOSStub_474c {
  strings:
    $key_474c = { 13 24 [2] 67 3c [2] 20 3e [2] 67 2f [2] 29 23 [2] 25 29 [2] 32 22 [2] 29 6c [2] 14 }

  condition:
    any of them
}