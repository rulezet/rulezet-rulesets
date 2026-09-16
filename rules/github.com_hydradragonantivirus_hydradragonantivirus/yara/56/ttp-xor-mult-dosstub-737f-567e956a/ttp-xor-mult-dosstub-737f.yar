rule TTP_XOR_MULT_DOSStub_737f {
  strings:
    $key_737f = { 27 17 [2] 53 0f [2] 14 0d [2] 53 1c [2] 1d 10 [2] 11 1a [2] 06 11 [2] 1d 5f [2] 20 }

  condition:
    any of them
}