rule TTP_XOR_MULT_DOSStub_2b3a {
  strings:
    $key_2b3a = { 7f 52 [2] 0b 4a [2] 4c 48 [2] 0b 59 [2] 45 55 [2] 49 5f [2] 5e 54 [2] 45 1a [2] 78 }

  condition:
    any of them
}