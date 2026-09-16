rule TTP_XOR_MULT_DOSStub_a26f {
  strings:
    $key_a26f = { f6 07 [2] 82 1f [2] c5 1d [2] 82 0c [2] cc 00 [2] c0 0a [2] d7 01 [2] cc 4f [2] f1 }

  condition:
    any of them
}