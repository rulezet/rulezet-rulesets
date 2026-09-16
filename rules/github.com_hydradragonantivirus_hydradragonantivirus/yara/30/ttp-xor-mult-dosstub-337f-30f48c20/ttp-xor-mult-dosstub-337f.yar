rule TTP_XOR_MULT_DOSStub_337f {
  strings:
    $key_337f = { 67 17 [2] 13 0f [2] 54 0d [2] 13 1c [2] 5d 10 [2] 51 1a [2] 46 11 [2] 5d 5f [2] 60 }

  condition:
    any of them
}