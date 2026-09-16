rule TTP_XOR_MULT_DOSStub_653a {
  strings:
    $key_653a = { 31 52 [2] 45 4a [2] 02 48 [2] 45 59 [2] 0b 55 [2] 07 5f [2] 10 54 [2] 0b 1a [2] 36 }

  condition:
    any of them
}