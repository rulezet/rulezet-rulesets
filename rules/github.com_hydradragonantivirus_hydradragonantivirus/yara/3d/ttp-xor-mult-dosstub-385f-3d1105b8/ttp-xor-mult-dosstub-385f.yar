rule TTP_XOR_MULT_DOSStub_385f {
  strings:
    $key_385f = { 6c 37 [2] 18 2f [2] 5f 2d [2] 18 3c [2] 56 30 [2] 5a 3a [2] 4d 31 [2] 56 7f [2] 6b }

  condition:
    any of them
}