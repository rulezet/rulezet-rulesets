rule TTP_XOR_MULT_DOSStub_bb5f {
  strings:
    $key_bb5f = { ef 37 [2] 9b 2f [2] dc 2d [2] 9b 3c [2] d5 30 [2] d9 3a [2] ce 31 [2] d5 7f [2] e8 }

  condition:
    any of them
}