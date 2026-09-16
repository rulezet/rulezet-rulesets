rule TTP_XOR_MULT_DOSStub_023a {
  strings:
    $key_023a = { 56 52 [2] 22 4a [2] 65 48 [2] 22 59 [2] 6c 55 [2] 60 5f [2] 77 54 [2] 6c 1a [2] 51 }

  condition:
    any of them
}