rule TTP_XOR_MULT_DOSStub_653c {
  strings:
    $key_653c = { 31 54 [2] 45 4c [2] 02 4e [2] 45 5f [2] 0b 53 [2] 07 59 [2] 10 52 [2] 0b 1c [2] 36 }

  condition:
    any of them
}