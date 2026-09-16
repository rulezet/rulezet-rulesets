rule TTP_XOR_MULT_DOSStub_2b1a {
  strings:
    $key_2b1a = { 7f 72 [2] 0b 6a [2] 4c 68 [2] 0b 79 [2] 45 75 [2] 49 7f [2] 5e 74 [2] 45 3a [2] 78 }

  condition:
    any of them
}