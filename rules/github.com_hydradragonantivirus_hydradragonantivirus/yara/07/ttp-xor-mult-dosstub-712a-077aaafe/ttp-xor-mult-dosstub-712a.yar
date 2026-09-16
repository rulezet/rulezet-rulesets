rule TTP_XOR_MULT_DOSStub_712a {
  strings:
    $key_712a = { 25 42 [2] 51 5a [2] 16 58 [2] 51 49 [2] 1f 45 [2] 13 4f [2] 04 44 [2] 1f 0a [2] 22 }

  condition:
    any of them
}