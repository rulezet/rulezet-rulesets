rule TTP_XOR_MULT_DOSStub_652a {
  strings:
    $key_652a = { 31 42 [2] 45 5a [2] 02 58 [2] 45 49 [2] 0b 45 [2] 07 4f [2] 10 44 [2] 0b 0a [2] 36 }

  condition:
    any of them
}