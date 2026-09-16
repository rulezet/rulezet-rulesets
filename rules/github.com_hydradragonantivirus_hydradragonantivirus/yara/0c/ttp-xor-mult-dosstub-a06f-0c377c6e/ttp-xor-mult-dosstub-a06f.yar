rule TTP_XOR_MULT_DOSStub_a06f {
  strings:
    $key_a06f = { f4 07 [2] 80 1f [2] c7 1d [2] 80 0c [2] ce 00 [2] c2 0a [2] d5 01 [2] ce 4f [2] f3 }

  condition:
    any of them
}