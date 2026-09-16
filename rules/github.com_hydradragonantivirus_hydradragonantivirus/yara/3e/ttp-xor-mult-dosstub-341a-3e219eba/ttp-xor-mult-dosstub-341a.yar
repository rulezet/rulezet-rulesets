rule TTP_XOR_MULT_DOSStub_341a {
  strings:
    $key_341a = { 60 72 [2] 14 6a [2] 53 68 [2] 14 79 [2] 5a 75 [2] 56 7f [2] 41 74 [2] 5a 3a [2] 67 }

  condition:
    any of them
}