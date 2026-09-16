rule TTP_XOR_MULT_DOSStub_440f {
  strings:
    $key_440f = { 10 67 [2] 64 7f [2] 23 7d [2] 64 6c [2] 2a 60 [2] 26 6a [2] 31 61 [2] 2a 2f [2] 17 }

  condition:
    any of them
}