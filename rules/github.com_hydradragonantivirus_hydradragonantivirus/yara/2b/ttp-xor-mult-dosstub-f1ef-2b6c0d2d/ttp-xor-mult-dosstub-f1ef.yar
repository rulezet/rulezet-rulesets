rule TTP_XOR_MULT_DOSStub_f1ef {
  strings:
    $key_f1ef = { a5 87 [2] d1 9f [2] 96 9d [2] d1 8c [2] 9f 80 [2] 93 8a [2] 84 81 [2] 9f cf [2] a2 }

  condition:
    any of them
}