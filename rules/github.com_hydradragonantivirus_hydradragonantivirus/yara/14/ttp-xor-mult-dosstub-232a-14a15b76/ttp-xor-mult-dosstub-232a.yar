rule TTP_XOR_MULT_DOSStub_232a {
  strings:
    $key_232a = { 77 42 [2] 03 5a [2] 44 58 [2] 03 49 [2] 4d 45 [2] 41 4f [2] 56 44 [2] 4d 0a [2] 70 }

  condition:
    any of them
}