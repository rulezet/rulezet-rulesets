rule TTP_XOR_MULT_DOSStub_052a {
  strings:
    $key_052a = { 51 42 [2] 25 5a [2] 62 58 [2] 25 49 [2] 6b 45 [2] 67 4f [2] 70 44 [2] 6b 0a [2] 56 }

  condition:
    any of them
}