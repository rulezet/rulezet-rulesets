rule TTP_XOR_MULT_DOSStub_d82f {
  strings:
    $key_d82f = { 8c 47 [2] f8 5f [2] bf 5d [2] f8 4c [2] b6 40 [2] ba 4a [2] ad 41 [2] b6 0f [2] 8b }

  condition:
    any of them
}