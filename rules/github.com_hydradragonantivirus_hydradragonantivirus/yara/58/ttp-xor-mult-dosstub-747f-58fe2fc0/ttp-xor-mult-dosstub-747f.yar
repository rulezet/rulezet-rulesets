rule TTP_XOR_MULT_DOSStub_747f {
  strings:
    $key_747f = { 20 17 [2] 54 0f [2] 13 0d [2] 54 1c [2] 1a 10 [2] 16 1a [2] 01 11 [2] 1a 5f [2] 27 }

  condition:
    any of them
}