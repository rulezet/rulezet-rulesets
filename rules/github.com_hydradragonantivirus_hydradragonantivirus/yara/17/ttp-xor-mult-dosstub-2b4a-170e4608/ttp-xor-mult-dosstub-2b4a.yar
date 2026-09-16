rule TTP_XOR_MULT_DOSStub_2b4a {
  strings:
    $key_2b4a = { 7f 22 [2] 0b 3a [2] 4c 38 [2] 0b 29 [2] 45 25 [2] 49 2f [2] 5e 24 [2] 45 6a [2] 78 }

  condition:
    any of them
}