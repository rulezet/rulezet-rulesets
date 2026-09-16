rule TTP_XOR_MULT_DOSStub_342a {
  strings:
    $key_342a = { 60 42 [2] 14 5a [2] 53 58 [2] 14 49 [2] 5a 45 [2] 56 4f [2] 41 44 [2] 5a 0a [2] 67 }

  condition:
    any of them
}