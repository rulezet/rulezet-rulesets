rule TTP_XOR_MULT_DOSStub_312a {
  strings:
    $key_312a = { 65 42 [2] 11 5a [2] 56 58 [2] 11 49 [2] 5f 45 [2] 53 4f [2] 44 44 [2] 5f 0a [2] 62 }

  condition:
    any of them
}